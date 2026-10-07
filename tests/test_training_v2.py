"""Integrity/split tests use fabricated small records, never accuracy claims."""
import json
from pathlib import Path
import zlib
import pytest
from training.expand_lanl import safe_target, expand_complete_records
from training.train_v2 import host_bucket, split_for, parse_record, prepare, Reservoir
from training.provenance import sha256
from backend.model import BehavioralModel

def test_expansion_keeps_complete_records_and_marks_partial_gzip(tmp_path):
    raw = b"1,U,C,P,Start\n2,U,C,P,End\n3,U,C,P,Start\n"
    compressor = zlib.compressobj(wbits=31)
    archive = compressor.compress(raw) + compressor.flush()
    prefix = tmp_path / "prefix.gz"
    prefix.write_bytes(archive[:-8])
    output = tmp_path / "output.txt"
    stats = expand_complete_records(prefix, output)
    assert output.read_bytes() == raw
    assert stats["complete_records"] == 3
    assert stats["gzip_footer_verified"] is False
    with pytest.raises(ValueError, match="bound"):
        expand_complete_records(prefix, output, max_expanded=10)

def test_expanded_target_cannot_overwrite_original_dataset(tmp_path):
    root = Path(__file__).resolve().parents[1]
    with pytest.raises(ValueError, match="separate subdirectory"):
        safe_target(root / "training/data")
    with pytest.raises(ValueError, match="separate subdirectory"):
        safe_target(tmp_path)
    assert safe_target(root / "training/data/lanl-v2-test").name == "lanl-v2-test"

def test_new_splits_exclude_all_v1_times_and_disjoint_host_buckets():
    hosts = {bucket: next(f"C{i}" for i in range(10000) if host_bucket(f"C{i}") == bucket) for bucket in (0, 6, 8)}
    assert split_for(hosts[0], 17910, 17911, 40000) is None
    assert split_for(hosts[0], 17911, 17911, 40000) == "train"
    assert split_for(hosts[6], 32000, 17911, 40000) == "validation"
    assert split_for(hosts[8], 39000, 17911, 40000) == "test"
    assert split_for(hosts[0], 39000, 17911, 40000) is None
    assert split_for(hosts[8], 20000, 17911, 40000) is None

def test_prepare_is_reproducible_excludes_duplicates_and_host_time_leakage(tmp_path):
    hosts = {bucket: next(f"C{i}" for i in range(10000) if host_bucket(f"C{i}") == bucket) for bucket in (0, 6, 8)}
    lines = ["1,U,C,P,Start\n"]
    for bucket, start in ((0, 18000), (6, 31500), (8, 36000)):
        for i in range(24 * 120):
            line = f"{start+i},U,{hosts[bucket]},P,{'Start' if i%2==0 else 'End'}\n"
            lines.append(line)
            if i == 0:
                lines.append(line)
    lines.append(f"40000,U,{hosts[8]},P,End\n")
    text = tmp_path / "lanl-proc.txt"
    text.write_text("".join(lines), encoding="ascii")
    prefix = tmp_path / "lanl-proc.prefix.gz"
    prefix.write_bytes(b"fabricated-integrity-fixture")
    manifest = {"mirror_revision": "a"*40, "v1_excluded_through_second": 17910,
        "partitions": [{"kind": "proc", "maximum_time": 40000, "source_url": "https://example.invalid/pinned",
            "prefix_bytes": prefix.stat().st_size, "prefix_sha256": sha256(prefix), "text_sha256": sha256(text)}]}
    (tmp_path / "lanl-manifest.json").write_text(json.dumps(manifest))
    reference = tmp_path / "reference.json"
    reference.write_text(json.dumps(manifest))
    first, stats, _ = prepare(tmp_path, reference, 100, 100)
    second, repeated, _ = prepare(tmp_path, reference, 100, 100)
    assert stats == repeated
    assert stats["duplicate_rows_excluded"]["proc"] == 3
    assert stats["records_time_excluded"]["proc"] == 1
    assert all((first[split] == second[split]).all() for split in first)
    assert all(len(array) == 100 and array.shape[1] == 24 for array in first.values())
    split_hosts = [set(stats["splits"][split]["hosts"]) for split in first]
    assert not any(left & right for index,left in enumerate(split_hosts) for right in split_hosts[index+1:])
    assert len({stats["splits"][split]["window_fingerprints_sha256"] for split in first}) == 3

def test_schema_rejects_wrong_process_rows_and_categorizes_ports():
    assert parse_record("proc", "100,U,C,P,Start\n") == (100,"C",0)
    assert parse_record("flows", "100,1,C1,5000,C2,3389,6,2,40\n") == (100,"C1",5)
    with pytest.raises(ValueError,match="schema"):
        parse_record("proc", "100,U,C,P,Unknown\n")

def test_reservoir_is_bounded_deterministic_and_samples_beyond_initial_prefix():
    first, second = Reservoir(20, 1984), Reservoir(20, 1984)
    for value in range(1000):
        first.add(value)
        second.add(value)
    assert first.items == second.items
    assert first.seen == 1000 and len(first.items) == 20
    assert max(first.items) > 900

def test_actual_frozen_v2_artifacts_preserve_selection_and_original_v1():
    root = Path(__file__).resolve().parents[1]
    out = root / "training/results/v2"
    freeze = json.loads((out / "selection-freeze.json").read_text())
    metrics = json.loads((out / "metrics.json").read_text())
    assert metrics["selection_freeze_sha256"] == sha256(out / "selection-freeze.json")
    assert freeze["dataset_manifest_sha256"] == sha256(root / "training/lanl-v2-manifest.json")
    assert freeze["splits_sha256"] == sha256(out / "splits.json")
    for candidate, expected in freeze["candidate_artifacts"].items():
        assert sha256(out / "models" / f"{candidate}.json") == expected
    runtime = BehavioralModel(out / "models")
    assert runtime.metadata["status"] == "available"
    assert runtime.metadata["artifact_sha256"] == freeze["candidate_artifacts"][freeze["selected_candidate"]]
    original = BehavioralModel(out / "v1-original")
    assert original.metadata["status"] == "available"
    assert original.metadata["version"].startswith("lanl2015-v1-")
    assert sha256(out / "v1-original/active.json") == freeze["v1_model_sha256"]
