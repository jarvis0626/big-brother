"""Bounded public OpTC acquisition. Dataset bytes are parsed, never executed.

Partial gzip archives are deliberately incomplete; hashes attest only the sampled
prefix. Resume uses HTTP byte ranges and validates the returned range.
"""
from __future__ import annotations
import argparse
import collections
import hashlib
import json
from pathlib import Path
import shutil
import urllib.request
import zlib

ROOT = Path(__file__).resolve().parents[1]
PARTITIONS = [
    ("benign-17-18Sep19", "1HQbZg4HoRxWbSt794YaDjaFRSQNJ3gMC", "AIA-51-75.ecar-2019-12-07T02-25-57.487.json.gz", 4433370679),
    ("benign-18-19Sep19", "1reiFMOZlA0IOejiDWLgHV5o2NAqVs7hf", "AIA-51-75.ecar-2019-12-07T07-21-29.412.json.gz", 174547807),
    ("benign-19Sep19", "1RVK5tuJr1vJ_c-8JWy36SRFZB3u6cSzx", "AIA-51-75.ecar-last.json.gz", 1701493537),
]

def sha256(path):
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

def download_prefix(url, path, limit):
    existing = path.stat().st_size if path.exists() else 0
    if existing > limit:
        raise ValueError("Existing prefix exceeds requested bound")
    if existing == limit:
        return
    # A cache may reuse an earlier range response when the URL is identical.
    req = urllib.request.Request(url+f"&sample_range={existing}-{limit-1}", headers={"Range": f"bytes={existing}-{limit-1}"})
    with urllib.request.urlopen(req, timeout=60) as response:
        expected = f"bytes {existing}-{limit-1}/"
        if response.status != 206 or not response.headers.get("Content-Range", "").startswith(expected):
            raise ValueError(f"Server did not honor bounded range ({response.status}, {response.headers.get('Content-Range')}); refusing full archive")
        with path.open("ab") as out:
            while existing < limit:
                chunk = response.read(min(1024*1024, limit-existing))
                if not chunk:
                    raise ValueError("Incomplete range response; rerun to resume")
                out.write(chunk)
                existing += len(chunk)

def decode(prefix, out_path, expanded_limit=256 * 1024 * 1024):
    decoder = zlib.decompressobj(31)
    buffer = b""
    counts = collections.Counter()
    records = 0
    expanded = 0
    minimum = maximum = None
    hosts = set()
    with prefix.open("rb") as source, out_path.open("w", encoding="utf8", newline="\n") as out:
        for chunk in iter(lambda: source.read(65536), b""):
            expanded_chunk = decoder.decompress(chunk, expanded_limit-expanded+1)
            expanded += len(expanded_chunk)
            if expanded > expanded_limit or decoder.unconsumed_tail:
                raise ValueError("Expansion limit exceeded")
            buffer += expanded_chunk
            lines = buffer.split(b"\n")
            buffer = lines.pop()
            if len(buffer) > 1024*1024:
                raise ValueError("Oversized unterminated record")
            for line in lines:
                if len(line) > 1024*1024:
                    counts["excluded:oversized"] += 1
                    continue
                try:
                    record = json.loads(line)
                except (ValueError, UnicodeError):
                    counts["excluded:malformed"] += 1
                    continue
                if not isinstance(record, dict):
                    continue
                pair = str(record.get("object"))+":"+str(record.get("action"))
                counts[pair] += 1
                stamp = str(record.get("timestamp", ""))
                if not stamp or len(stamp) > 80:
                    continue
                # Store actual fields without interpreting embedded command strings.
                normalized = {k: record.get(k) for k in
                              ("id", "timestamp", "hostname", "actorID", "objectID", "object", "action", "pid", "ppid")}
                normalized["properties"] = {
                    str(k)[:80]: str(v)[:4096] for k,v in (record.get("properties") or {}).items()
                    if k in {"dest_ip", "dest_port", "l4protocol", "image_path", "parent_image_path"}
                }
                out.write(json.dumps(normalized, ensure_ascii=True, separators=(",", ":"))+"\n")
                hosts.add(str(record.get("hostname")))
                minimum = min(minimum, stamp) if minimum else stamp
                maximum = max(maximum, stamp) if maximum else stamp
                records += 1
    return {"records": records, "expanded_bytes": expanded, "normalized_bytes": out_path.stat().st_size,
            "excluded_partial_final_line_bytes": len(buffer), "gzip_footer_verified": decoder.eof,
            "raw_object_action_counts": dict(counts), "timestamp_min": minimum, "timestamp_max": maximum,
            "hosts": sorted(hosts), "normalized_sha256": sha256(out_path)}

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--prefix-mib", type=int, default=8)
    args = parser.parse_args()
    if not 1 <= args.prefix_mib <= 16:
        parser.error("Prefix must be 1..16 MiB; total compressed acquisition is at most 48 MiB")
    target = ROOT / "training" / "data"
    target.mkdir(parents=True, exist_ok=True)
    disk = shutil.disk_usage(target)
    if (disk.free - 1024**3) / disk.total < .20:
        raise RuntimeError("Download would infringe the 20% disk reserve")
    docs = ROOT / "training" / "sources"
    docs.mkdir(parents=True, exist_ok=True)
    for name in ("README.md", "ecar.md", "errata.md"):
        url = "https://raw.githubusercontent.com/FiveDirections/OpTC-data/master/"+name
        with urllib.request.urlopen(url, timeout=30) as response:
            data = response.read(128*1024+1)
        if len(data) > 128*1024:
            raise ValueError("Documentation bound exceeded")
        (docs/name).write_bytes(data)
    manifest = {"dataset": "DARPA Operationally Transparent Cyber (OpTC)",
                "official_source": "https://github.com/FiveDirections/OpTC-data",
                "official_release_folder": "https://drive.google.com/drive/folders/1n3kkS3KR31KUegn42yk3-e6JkZvf0Caa",
                "licence": "DARPA public domain; Distribution A, approved for public release, distribution unlimited",
                "acquired_on": "2026-10-07", "selection": "First bounded compressed bytes of three benign AIA51-75 date partitions; not random, not complete",
                "attack_labels": "Not used. Benign-folder provenance only; does not prove each record is benign.",
                "official_total_compressed_size": "Approximately one terabyte", "partitions": [],
                "docs_sha256": {p.name: sha256(p) for p in docs.glob("*.md")}}
    for name, file_id, filename, archive_size in PARTITIONS:
        url = f"https://drive.usercontent.google.com/download?id={file_id}&export=download&confirm=t"
        prefix = target / (name+".prefix.gz")
        out = target / (name+".jsonl")
        download_prefix(url, prefix, args.prefix_mib*1024*1024)
        stats = decode(prefix, out)
        item = {"name": name, "source_url": url, "official_filename": filename,
                "official_compressed_bytes": archive_size, "byte_range": [0, prefix.stat().st_size-1],
                "downloaded_bytes": prefix.stat().st_size, "prefix_sha256": sha256(prefix),
                "complete_archive": False, **stats}
        manifest["partitions"].append(item)
        (target/"manifest.json").write_text(json.dumps(manifest, indent=2)+"\n", encoding="utf8")
        print(json.dumps({"partition": name, **stats}), flush=True)
    print("Manifest:",target/"manifest.json",flush=True)

if __name__ == "__main__":
    main()
