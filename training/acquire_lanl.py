"""Bounded, resumable acquisition of public-domain LANL2015 raw telemetry.

Official direct source is registration-gated; this public copy records direct
official acquisition. Full-file publisher hashes are recorded, prefix hashes
are measured. Full official byte equivalence is a publisher claim, not ours.
"""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import re
import shutil
import urllib.request
import zlib
from acquire_mirror import fetch, sha256

ROOT = Path(__file__).resolve().parents[1]
REPO = "Taqui/lanl-cyber-datasets"
DEFAULT_REVISION = "d7a15d0d504051bfe6cbc3f65377830704e824cc"
HASHES = {
    "proc": (2358611874, "af82f47ebf3ffc6dc392a01f890caa6157a5c7581a2cf0b1821801347f293ae4"),
    "flows": (1083479090, "60e0cfeae74f820e7dad42a06291941bd329b547439f12705435927278082f98"),
    "dns": (185104940, "3e1cb718baa6be7af7bd376324285be45d99ee2563d22bc4abf023572120cab9"),
}

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--prefix-mib", type=int, default=4)
    parser.add_argument("--revision", default=DEFAULT_REVISION,
                        help="Immutable 40-character mirror commit; default reproduces the shipped experiment")
    parser.add_argument("--data-dir", type=Path,
                        help="Separate raw-data directory; required when acquiring a different revision")
    args = parser.parse_args()
    if not 1 <= args.prefix_mib <= 8:
        parser.error("Bound is 1..8 MiB per source")
    if not re.fullmatch(r"[0-9a-fA-F]{40}",args.revision):
        parser.error("--revision must be an immutable 40-character commit SHA, not a moving branch/tag")
    revision=args.revision.lower()
    default_target=(ROOT/"training/data").resolve()
    target=args.data_dir.resolve() if args.data_dir else default_target
    new_experiment=revision!=DEFAULT_REVISION
    if new_experiment and (args.data_dir is None or target==default_target):
        parser.error("A different revision is a new experiment; specify a separate --data-dir")
    existing_manifest=target/"lanl-manifest.json"
    if existing_manifest.exists():
        prior=json.loads(existing_manifest.read_text(encoding="utf8"))
        if prior.get("mirror_revision")!=revision:
            parser.error("Existing data directory belongs to another revision; use a separate --data-dir")
    reference_path=ROOT/"training/dataset-manifest.json"
    reference=json.loads(reference_path.read_text(encoding="utf8")) if reference_path.exists() else None
    expected_parts={p["kind"]:p for p in reference["partitions"]} if reference and reference["mirror_revision"]==revision and args.prefix_mib==4 else {}
    target.mkdir(parents=True, exist_ok=True)
    disk = shutil.disk_usage(target)
    if (disk.free-1024**3)/disk.total < .20:
        raise RuntimeError("Insufficient 20% reserve")
    publisher_hashes=HASHES
    if new_experiment:
        # A new revision must not inherit stale publisher hashes from this run.
        listing=json.load(urllib.request.urlopen(f"https://huggingface.co/api/datasets/{REPO}/tree/{revision}/lanl-2015?limit=1000",timeout=30))
        entries={item["path"]:item for item in listing}
        publisher_hashes={}
        for kind in HASHES:
            entry=entries[f"lanl-2015/{kind}.txt.gz"]
            fullhash=entry["lfs"]["oid"]
            if not re.fullmatch(r"[0-9a-f]{64}",fullhash):raise ValueError("Invalid publisher SHA256")
            publisher_hashes[kind]=(int(entry["size"]),fullhash)
    readme = urllib.request.urlopen(f"https://huggingface.co/datasets/{REPO}/raw/{revision}/README.md",timeout=30).read(32768)
    sources = target/"sources" if new_experiment else ROOT / "training" / "sources"
    sources.mkdir(exist_ok=True, parents=True)
    (sources/"lanl-mirror-README.md").write_bytes(readme)
    official_doc = urllib.request.urlopen("https://csr.lanl.gov/data/cyber1/",timeout=30).read(131072)
    (sources/"lanl2015-official.html").write_bytes(official_doc)
    manifest = {"dataset": "LANL Comprehensive Multi-Source Cybersecurity Events (2015), bounded raw prefixes",
        "official_source": "https://csr.lanl.gov/data/cyber1/", "doi": "10.17021/1179829",
        "licence": "LANL waived all copyright and related rights to this dataset (public-domain/CC0-style waiver)",
        "attribution": "A. D. Kent, Comprehensive, Multi-Source Cybersecurity Events, LANL, 2015; Cybersecurity Data Sources for Dynamic Network Research, 2015",
        "mirror": "https://huggingface.co/datasets/"+REPO, "mirror_revision": revision,
        "provenance": "Publisher states raw byte-identical copies acquired exclusively from official LANL source. Schema verified against official documentation; full-file equality to official archives cannot independently be checked without downloading registration-gated originals.",
        "acquired_on": "2026-10-07", "selection": f"First{args.prefix_mib}MiB compressed of proc, flows, dns. Biased prefix, not full release. Time intersection and disjoint hosts/time splits applied by train.py.",
        "official_release_size": "Approximately12GB compressed; 58days;1,648,275,307events",
        "label_interpretation": "No redteam labels downloaded. No classification or malware-detection metrics. Anomaly/predictive objectives only.",
        "excluded_other_acquisitions": "OpTC-derived public Parquet files inspected but excluded due undocumented conversion provenance; official OpTC requests quota-blocked. Initial official4KB sample not used for training.",
        "schema": {"proc":"time,user@domain,computer,anonymized process name,start/end (no PID or parent)","flows":"time,duration,source computer,source port,destination computer,destination port,protocol,packets,bytes (no process attribution)","dns":"time,source computer,resolved computer"},
        "partitions": []}
    if new_experiment:
        manifest["new_experiment"]=True
        manifest["shipped_reference_revision"]=DEFAULT_REVISION
    for kind,(total,fullhash) in publisher_hashes.items():
        url=f"https://huggingface.co/datasets/{REPO}/resolve/{revision}/lanl-2015/{kind}.txt.gz?download=true"
        prefix=target/("lanl-"+kind+".prefix.gz")
        fetch(url,prefix,args.prefix_mib*1024*1024)
        expected=expected_parts.get(kind)
        if expected and sha256(prefix)!=expected["prefix_sha256"]:
            raise ValueError("Acquired prefix differs from the tracked shipped-experiment SHA256: "+kind)
        decoder=zlib.decompressobj(31)
        expanded=0
        out=target/("lanl-"+kind+".txt")
        with prefix.open("rb") as source,out.open("wb") as dest:
            for chunk in iter(lambda: source.read(65536),b""):
                data=decoder.decompress(chunk,128*1024*1024-expanded+1)
                expanded+=len(data)
                if expanded>128*1024*1024 or decoder.unconsumed_tail:
                    raise ValueError("Decompression exceeds128MiB bound")
                dest.write(data)
        # Retain only complete lines. Incomplete gzip footer is explicit.
        with out.open("r+b") as f:
            f.seek(max(0,expanded-8192));tail=f.read();last=tail.rfind(b"\n")
            if last<0:raise ValueError("Missing bounded record newline")
            f.truncate(max(0,expanded-8192)+last+1)
        records=0;minimum=maximum=None
        with out.open("rb") as f:
            for line in f:
                if len(line)>8192:raise ValueError("Oversized LANL record")
                t=int(line.split(b",",1)[0]);records+=1
                minimum=min(t,minimum) if minimum is not None else t
                maximum=max(t,maximum) if maximum is not None else t
        item={"kind":kind,"source_url":url,"prefix_bytes":prefix.stat().st_size,"byte_range":[0,prefix.stat().st_size-1],
              "prefix_sha256":sha256(prefix),"publisher_full_archive_sha256":fullhash,"publisher_full_archive_bytes":total,
              "full_archive_hash_verified":False,"gzip_footer_verified":decoder.eof,"complete_archive":False,
              "complete_records":records,"expanded_bytes":expanded,"usable_bytes":out.stat().st_size,
              "text_sha256":sha256(out),"minimum_time":minimum,"maximum_time":maximum}
        if expected and item["text_sha256"]!=expected["text_sha256"]:
            raise ValueError("Decoded data differs from the tracked shipped-experiment SHA256: "+kind)
        manifest["partitions"].append(item)
        (target/"lanl-manifest.json").write_text(json.dumps(manifest,indent=2)+"\n",encoding="utf8")
        print(json.dumps(item),flush=True)

if __name__=="__main__":main()
