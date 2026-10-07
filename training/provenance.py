"""Standard-library verification of the pinned experiment's data provenance."""
import hashlib
import json
from pathlib import Path

def sha256(path):
    value=hashlib.sha256()
    with Path(path).open("rb") as source:
        for chunk in iter(lambda:source.read(1024*1024),b""):value.update(chunk)
    return value.hexdigest()

def validate_dataset_manifest(data,reference_path):
    data=Path(data)
    manifest=json.loads((data/"lanl-manifest.json").read_text(encoding="utf8"))
    reference=json.loads(Path(reference_path).read_text(encoding="utf8"))
    if manifest.get("mirror_revision")!=reference["mirror_revision"]:
        raise ValueError("Data revision does not match the tracked experiment manifest")
    expected={p["kind"]:p for p in reference["partitions"]}
    actual={p["kind"]:p for p in manifest["partitions"]}
    if set(actual)!=set(expected) or len(manifest["partitions"])!=len(expected):
        raise ValueError("Dataset partitions differ from the tracked experiment manifest")
    for kind,part in actual.items():
        for field in ("source_url","prefix_bytes","prefix_sha256","text_sha256"):
            if part[field]!=expected[kind][field]:
                raise ValueError("Dataset provenance differs from tracked manifest: "+kind+"/"+field)
        prefix=data/("lanl-"+kind+".prefix.gz")
        if prefix.stat().st_size!=part["prefix_bytes"] or sha256(prefix)!=part["prefix_sha256"]:
            raise ValueError("Raw archive prefix checksum mismatch: "+kind)
        if sha256(data/("lanl-"+kind+".txt"))!=part["text_sha256"]:
            raise ValueError("Decoded dataset checksum mismatch: "+kind)
    return manifest
