"""Acquire complete small OpTC-derived public mirror files, never execute records.

The original DARPA release is public domain. These converted files are third-party
copies without conversion documentation; see dataset-card.md for that limitation.
"""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
import shutil
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
REPO = "equalNull/testing-optc-sep17"
REVISION = "4895b7324e7ba8a2916463d7ba530f152b26321d"
FILES = [
    ("train", "AIA-351-375.ecar-2019-09-17-sysclient0356.parquet", 9804045, "cc3299ffeb746c03358bd8312e3a725279b6f67cb1e06cdb0ea1741f0f49fcf1"),
    ("validation", "AIA-426-450.ecar-2019-09-17-sysclient0440.parquet", 10459618, "c4616e2b65e2223254c6be056e4e8e08faa4424c3cb568d56e7926c5374c759a"),
    ("test", "AIA-451-475.ecar-2019-09-17-sysclient0467.parquet", 10803870, "a844349231c3b9e8ed7188c8aebc0637cea9e293bf60023f10880a47a0daaa97"),
]

def sha256(path):
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024*1024), b""):
            h.update(chunk)
    return h.hexdigest()

def fetch(url, path, size):
    existing = path.stat().st_size if path.exists() else 0
    if existing > size:
        raise ValueError("Existing file exceeds declared size")
    if existing == size:
        return
    req = urllib.request.Request(url, headers={"Range": f"bytes={existing}-{size-1}"})
    with urllib.request.urlopen(req, timeout=60) as response:
        valid_range = response.status == 206 and response.headers.get("Content-Range", "").startswith(f"bytes {existing}-{size-1}/")
        valid_complete = existing == 0 and response.status == 200 and int(response.headers.get("Content-Length", "0")) == size
        if not (valid_range or valid_complete):
            raise ValueError("Response is not the bounded requested file/range")
        with path.open("ab") as out:
            while existing < size:
                block = response.read(min(1024*1024, size-existing))
                if not block:
                    raise IOError("Incomplete response; rerun to resume")
                out.write(block)
                existing += len(block)

def main():
    import pyarrow.parquet as pq
    target = ROOT / "training" / "data"
    target.mkdir(parents=True, exist_ok=True)
    disk = shutil.disk_usage(target)
    if (disk.free - 1024**3) / disk.total < .20:
        raise RuntimeError("Download would infringe the 20% disk reserve")
    manifest = {
        "dataset": "OpTC-derived eCAR public third-party Parquet sample",
        "official_source": "https://github.com/FiveDirections/OpTC-data",
        "official_release_licence": "DARPA public domain; Distribution A, distribution unlimited",
        "mirror_repository": "https://huggingface.co/datasets/"+REPO,
        "mirror_revision": REVISION, "acquired_on": "2026-10-07",
        "provenance_verification": "Format/fields match official eCAR; publisher LFS SHA256 verified. Official archive byte equivalence and mirror conversion completeness cannot be verified. Mirror supplies no README or conversion documentation.",
        "original_access_blocker": "Official public Google Drive partitions returned quota-exceeded pages after the initial bounded 4096-byte response. LANL2017 direct public URLs require registration (HTTP401). No access controls bypassed.",
        "selection": "Three smallest complete host files in Sep17 mirror; one train host356, validation host440, test host467; budget31,067,533bytes. Host/activity-size selection bias.",
        "labels": "No attack labels acquired or used. Original folder date is within benign collection, but individual records are not independently verified benign.",
        "split": "Disjoint hosts by complete file; chronological order within each host; exact duplicate sequence exclusion recorded by train.py",
        "partitions": [],
    }
    for split, filename, size, expected in FILES:
        url = f"https://huggingface.co/datasets/{REPO}/resolve/{REVISION}/data_flush/{filename}?download=true"
        path = target / filename
        fetch(url,path,size)
        actual = sha256(path)
        if actual != expected:
            raise ValueError("Publisher SHA256 mismatch: "+filename)
        pf = pq.ParquetFile(path)
        item = {"split": split, "filename": filename, "source_url": url,
                "downloaded_bytes": size, "sha256": actual, "publisher_lfs_sha256": expected,
                "sha256_verified": True, "complete_mirror_file": True,
                "records": pf.metadata.num_rows, "row_groups": pf.metadata.num_row_groups,
                "schema": str(pf.schema_arrow)}
        manifest["partitions"].append(item)
        (target/"manifest.json").write_text(json.dumps(manifest, indent=2)+"\n",encoding="utf8")
        print(json.dumps(item),flush=True)
    print("Complete bounded files verified",flush=True)

if __name__ == "__main__":
    main()
