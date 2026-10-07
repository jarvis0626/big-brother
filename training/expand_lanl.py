"""Acquire an isolated larger, immutable LANL prefix experiment on D:.

This never overwrites the shipped v1 manifest/data. Partial gzip archives are
explicitly identified, and both downloaded bytes and complete records are hashed.
"""
from __future__ import annotations
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import shutil
import sys
import urllib.request
import zlib

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from training.acquire_mirror import fetch, sha256

REVISION = "d7a15d0d504051bfe6cbc3f65377830704e824cc"
REPO = "Taqui/lanl-cyber-datasets"
ARCHIVES = {
    "proc": (2358611874, "af82f47ebf3ffc6dc392a01f890caa6157a5c7581a2cf0b1821801347f293ae4"),
    "flows": (1083479090, "60e0cfeae74f820e7dad42a06291941bd329b547439f12705435927278082f98"),
    "dns": (185104940, "3e1cb718baa6be7af7bd376324285be45d99ee2563d22bc4abf023572120cab9"),
}

def safe_target(target):
    target = Path(target).resolve()
    allowed = (ROOT / "training/data").resolve()
    if not target.is_relative_to(allowed) or target == allowed:
        raise ValueError("Expanded raw data must use a separate subdirectory of training/data on D:")
    return target

def expand_complete_records(prefix, output, max_expanded=1024**3):
    decoder = zlib.decompressobj(31)
    expanded = 0
    with Path(prefix).open("rb") as source, Path(output).open("wb") as dest:
        for chunk in iter(lambda: source.read(65536), b""):
            block = decoder.decompress(chunk, max_expanded - expanded + 1)
            expanded += len(block)
            if expanded > max_expanded or decoder.unconsumed_tail:
                raise ValueError("Decompression exceeds the explicit per-file bound")
            dest.write(block)
    with Path(output).open("r+b") as dest:
        offset = max(0, expanded - 8192)
        dest.seek(offset)
        tail = dest.read()
        last = tail.rfind(b"\n")
        if last < 0:
            raise ValueError("No complete bounded final record")
        dest.truncate(offset + last + 1)
    count = 0
    low = high = None
    with Path(output).open("rb") as source:
        for line in source:
            if len(line) > 8192:
                raise ValueError("Oversized LANL record")
            stamp = int(line.split(b",", 1)[0])
            if high is not None and stamp < high:
                raise ValueError("LANL source is not chronologically ordered")
            count += 1
            low = stamp if low is None else low
            high = stamp
    return {"complete_records": count, "minimum_time": low, "maximum_time": high,
            "expanded_bytes": expanded, "usable_bytes": Path(output).stat().st_size,
            "gzip_footer_verified": decoder.eof, "complete_archive": decoder.eof}

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--prefix-mib", type=int, default=32)
    parser.add_argument("--data-dir", type=Path, default=ROOT / "training/data/lanl-v2-32mib")
    args = parser.parse_args()
    if not 16 <= args.prefix_mib <= 64:
        parser.error("Expanded bound is 16..64 MiB per source")
    target = safe_target(args.data_dir)
    target.mkdir(parents=True, exist_ok=True)
    reserve = 3 * (1024**3 + args.prefix_mib * 1024**2)
    disk = shutil.disk_usage(target)
    if (disk.free - reserve) / disk.total < .20:
        raise RuntimeError("Expansion would breach D: 20% free-space reserve")
    reference = ROOT / "training/lanl-v2-manifest.json"
    existing = target / "lanl-manifest.json"
    expected = json.loads(reference.read_text(encoding="utf8")) if reference.exists() else None
    if existing.exists():
        prior = json.loads(existing.read_text(encoding="utf8"))
        if prior["mirror_revision"] != REVISION or prior["prefix_mib"] != args.prefix_mib:
            raise ValueError("Existing experiment has different revision or prefix bound")
    original = json.loads((ROOT / "training/dataset-manifest.json").read_text(encoding="utf8"))
    manifest = {key: original[key] for key in ("dataset", "official_source", "doi", "licence", "attribution", "mirror", "provenance", "schema")}
    manifest.update({"experiment": "lanl-v2-later-time", "mirror_revision": REVISION,
        "acquired_utc": datetime.now(timezone.utc).isoformat(), "prefix_mib": args.prefix_mib,
        "selection": "First bounded compressed bytes of proc/flows/dns; biased prefix rather than full release. Training excludes all timestamps used in v1, and uses new host/time-disjoint splits.",
        "label_interpretation": "No attack labels; next-event prediction and unlabelled threshold exceedances only.",
        "v1_excluded_through_second": min(part["maximum_time"] for part in original["partitions"]),
        "partitions": []})
    for kind, (full_size, full_sha) in ARCHIVES.items():
        url = f"https://huggingface.co/datasets/{REPO}/resolve/{REVISION}/lanl-2015/{kind}.txt.gz?download=true&experiment=v2-{args.prefix_mib}mib"
        prefix = target / f"lanl-{kind}.prefix.gz"
        fetch(url, prefix, args.prefix_mib * 1024**2)
        output = target / f"lanl-{kind}.txt"
        item = expand_complete_records(prefix, output)
        item.update({"kind": kind, "source_url": url, "prefix_bytes": prefix.stat().st_size,
            "prefix_sha256": sha256(prefix), "text_sha256": sha256(output),
            "byte_range": [0, prefix.stat().st_size - 1], "publisher_full_archive_bytes": full_size,
            "publisher_full_archive_sha256": full_sha, "full_archive_hash_verified": False})
        if expected:
            match = next(part for part in expected["partitions"] if part["kind"] == kind)
            if any(item[key] != match[key] for key in ("source_url", "prefix_bytes", "prefix_sha256", "text_sha256")):
                raise ValueError("Expanded download differs from frozen experiment: " + kind)
        manifest["partitions"].append(item)
        existing.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf8")
        print(json.dumps(item), flush=True)
    if not reference.exists():
        reference.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf8")
    print("Expanded experiment provenance frozen: " + str(reference), flush=True)

if __name__ == "__main__":
    main()
