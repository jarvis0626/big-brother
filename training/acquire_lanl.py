"""Bounded, resumable acquisition of public-domain LANL2015 raw telemetry.

Official direct source is registration-gated; this public copy records direct
official acquisition. Full-file publisher hashes are recorded, prefix hashes
are measured. Full official byte equivalence is a publisher claim, not ours.
"""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import shutil
import urllib.request
import zlib
from acquire_mirror import fetch, sha256

ROOT = Path(__file__).resolve().parents[1]
REPO = "Taqui/lanl-cyber-datasets"
HASHES = {
    "proc": (2358611874, "af82f47ebf3ffc6dc392a01f890caa6157a5c7581a2cf0b1821801347f293ae4"),
    "flows": (1083479090, "60e0cfeae74f820e7dad42a06291941bd329b547439f12705435927278082f98"),
    "dns": (185104940, "3e1cb718baa6be7af7bd376324285be45d99ee2563d22bc4abf023572120cab9"),
}

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--prefix-mib", type=int, default=4)
    args = parser.parse_args()
    if not 1 <= args.prefix_mib <= 8:
        parser.error("Bound is 1..8 MiB per source")
    target = ROOT / "training" / "data"
    target.mkdir(parents=True, exist_ok=True)
    disk = shutil.disk_usage(target)
    if (disk.free-1024**3)/disk.total < .20:
        raise RuntimeError("Insufficient 20% reserve")
    info = json.load(urllib.request.urlopen("https://huggingface.co/api/datasets/"+REPO,timeout=30))
    revision = info["sha"]
    readme = urllib.request.urlopen(f"https://huggingface.co/datasets/{REPO}/raw/{revision}/README.md",timeout=30).read(32768)
    sources = ROOT / "training" / "sources"
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
    for kind,(total,fullhash) in HASHES.items():
        url=f"https://huggingface.co/datasets/{REPO}/resolve/{revision}/lanl-2015/{kind}.txt.gz?download=true"
        prefix=target/("lanl-"+kind+".prefix.gz")
        fetch(url,prefix,args.prefix_mib*1024*1024)
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
        manifest["partitions"].append(item)
        (target/"lanl-manifest.json").write_text(json.dumps(manifest,indent=2)+"\n",encoding="utf8")
        print(json.dumps(item),flush=True)

if __name__=="__main__":main()
