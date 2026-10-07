import copy
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import pytest
from training.provenance import validate_dataset_manifest,sha256

ROOT=Path(__file__).resolve().parents[1]

def fixture_manifest(tmp_path):
    # Tiny fabricated byte fixtures test integrity handling, not model accuracy.
    prefix=tmp_path/"lanl-proc.prefix.gz";prefix.write_bytes(b"bounded-prefix")
    text=tmp_path/"lanl-proc.txt";text.write_bytes(b"1,U1,C1,P1,Start\n")
    manifest={"mirror_revision":"a"*40,"partitions":[{"kind":"proc","source_url":"https://example.invalid/pinned",
        "prefix_bytes":prefix.stat().st_size,"prefix_sha256":sha256(prefix),"text_sha256":sha256(text)}]}
    local=tmp_path/"lanl-manifest.json";local.write_text(json.dumps(manifest))
    reference=tmp_path/"reference.json";reference.write_text(json.dumps(manifest))
    return manifest,local,reference,prefix,text

def test_changed_prefix_or_text_fails_before_preprocessing(tmp_path):
    manifest,local,reference,prefix,text=fixture_manifest(tmp_path)
    assert validate_dataset_manifest(tmp_path,reference)==manifest
    prefix.write_bytes(b"changed-prefix")
    with pytest.raises(ValueError,match="prefix checksum"):
        validate_dataset_manifest(tmp_path,reference)
    prefix.write_bytes(b"bounded-prefix")
    text.write_bytes(b"changed decoded data")
    with pytest.raises(ValueError,match="Decoded dataset checksum"):
        validate_dataset_manifest(tmp_path,reference)

def test_changed_revision_or_source_url_cannot_relabel_cached_data(tmp_path):
    manifest,local,reference,_,_=fixture_manifest(tmp_path)
    altered=copy.deepcopy(manifest);altered["mirror_revision"]="b"*40
    local.write_text(json.dumps(altered))
    with pytest.raises(ValueError,match="revision"):
        validate_dataset_manifest(tmp_path,reference)
    altered=copy.deepcopy(manifest);altered["partitions"][0]["source_url"]="https://example.invalid/other"
    local.write_text(json.dumps(altered))
    with pytest.raises(ValueError,match="provenance"):
        validate_dataset_manifest(tmp_path,reference)

def test_tracked_manifest_matches_saved_original_experiment():
    path=ROOT/"training/dataset-manifest.json"
    metrics=json.loads((ROOT/"training/results/metrics.json").read_text())
    assert sha256(path)==metrics["dataset_manifest_sha256"]
    manifest=json.loads(path.read_text())
    assert manifest["mirror_revision"]=="d7a15d0d504051bfe6cbc3f65377830704e824cc"
    assert len(manifest["partitions"])==3

@pytest.mark.parametrize("args,reason",[( ["--revision","main"],"immutable"),(["--revision","b"*40],"new experiment")])
def test_acquisition_rejects_moving_or_mixed_revision_before_io(args,reason):
    result=subprocess.run([sys.executable,str(ROOT/"training/acquire_lanl.py"),*args],capture_output=True,text=True)
    assert result.returncode==2
    assert reason in result.stderr
