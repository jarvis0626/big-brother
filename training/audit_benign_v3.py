"""Acquire and audit the small, inert SILRAD feature release, without fitting.

Only publisher metadata and ZIP text/CSV members are read. No downloaded code
or binaries are extracted or executed. Data stays under ignored training/data.
"""
from __future__ import annotations

import argparse
from collections import Counter
import csv
from datetime import datetime, timezone
import hashlib
import io
import json
from pathlib import Path
import re
import shutil
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "training" / "data" / "v3" / "silrad"
MANIFEST = ROOT / "training" / "benign-v3-manifest.json"
METADATA_URL = "https://zenodo.org/api/records/17104902"
ARCHIVE_URL = "https://zenodo.org/records/17104902/files/JamilIsp/SILRAD-dataset-SILRAD-1.0.zip?download=1"
ARCHIVE_BYTES = 3_587_892
ARCHIVE_MD5 = "05a032e64076721bd42c5e63288b0baa"
PREFIX = "JamilIsp-SILRAD-dataset-d4a3625/"
CSV_BYTES = {"fasttext-all-nofamily.csv": 89_690_388,
             "fasttext-testmodel.csv": 71_427_377,
             "fasttext-trainmodel.csv": 18_263_460}
GUID = re.compile(r"^\{?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}?$", re.I)


def fetch(url, limit):
    request = urllib.request.Request(url, headers={"User-Agent": "Big-Brother-benign-source-audit"})
    with urllib.request.urlopen(request, timeout=45) as incoming:
        content = incoming.read(limit + 1)
    if len(content) > limit:
        raise ValueError("Publisher response exceeds the acquisition bound")
    return content


def acquire():
    DATA.mkdir(parents=True, exist_ok=True)
    usage = shutil.disk_usage(DATA)
    # This bounded 3.6 MB audit stores no expanded CSVs. Preserve 1 GiB even
    # when unrelated user files have consumed the old bulk-download reserve.
    if usage.free - 16 * 1024**2 < 1024**3:
        raise ValueError("Acquisition would leave less than 1 GiB free")
    archive = DATA / "publisher-release.zip"
    if not archive.exists():
        content = fetch(ARCHIVE_URL, ARCHIVE_BYTES)
        verify_archive(content)
        partial = archive.with_suffix(".part")
        partial.write_bytes(content)
        partial.replace(archive)
    verify_archive(archive.read_bytes())
    metadata = fetch(METADATA_URL, 1024**2)
    parsed = json.loads(metadata)
    if parsed.get("id") != 17104902 or parsed["metadata"].get("license", {}).get("id") != "cc-by-4.0":
        raise ValueError("Publisher record or declared data license changed; review required")
    (DATA / "publisher-metadata.json").write_bytes(metadata)
    return archive, parsed


def verify_archive(content):
    if len(content) != ARCHIVE_BYTES or hashlib.md5(content).hexdigest() != ARCHIVE_MD5:
        raise ValueError("Publisher release size or MD5 mismatch")


def audit(archive, metadata):
    raw = archive.read_bytes()
    verify_archive(raw)
    results, fingerprints = {}, {}
    csv.field_size_limit(128 * 1024)
    with zipfile.ZipFile(io.BytesIO(raw)) as outer:
        allowed = {PREFIX + "README.md", PREFIX + "SILRAD-dataset.zip"}
        if {entry.filename for entry in outer.infolist() if not entry.is_dir()} != allowed:
            raise ValueError("Unexpected publisher release members")
        inner_info = outer.getinfo(PREFIX + "SILRAD-dataset.zip")
        if inner_info.file_size > 8 * 1024**2:
            raise ValueError("Nested feature ZIP exceeds its bound")
        inner_raw = outer.read(inner_info)
        readme = outer.read(PREFIX + "README.md")
        if len(readme) > 64 * 1024:
            raise ValueError("Publisher README exceeds its bound")
        # Save whitelisted text provenance; all CSVs are streamed, never extracted.
        (DATA / "publisher-README.md").write_bytes(readme)
        with zipfile.ZipFile(io.BytesIO(inner_raw)) as inner:
            if set(inner.namelist()) != set(CSV_BYTES):
                raise ValueError("Unexpected nested feature members")
            for name, expected in CSV_BYTES.items():
                info = inner.getinfo(name)
                if info.file_size != expected:
                    raise ValueError("Feature member size changed")
                classes, events, identity = Counter(), Counter(), Counter()
                feature_hashes = set()
                digest = hashlib.sha256()
                rows, repeated = 0, 0
                with inner.open(name) as incoming:
                    text = io.TextIOWrapper(incoming, encoding="utf-8-sig", newline="")
                    reader = csv.DictReader(text)
                    columns = reader.fieldnames
                    if not columns or len(columns) > 128 or "class" not in columns:
                        raise ValueError("Unsupported CSV header")
                    for row in reader:
                        if None in row or any(value is None for value in row.values()):
                            raise ValueError("Malformed CSV row")
                        rows += 1
                        if rows > 300_000:
                            raise ValueError("CSV record count exceeds its bound")
                        classes[row["class"]] += 1
                        events[row.get("event.code", "")] += 1
                        for field in ("ProcessGuid", "ParentProcessGuid"):
                            identity[field + "_valid_guid"] += bool(GUID.fullmatch(row.get(field, "")))
                        for field in ("ProcessId", "ParentProcessId"):
                            value = row.get(field, "")
                            identity[field + "_nonnegative_integer"] += value.isdecimal()
                        values = [row[key] for key in columns if key != "class"]
                        encoded = json.dumps(values, ensure_ascii=False, separators=(",", ":")).encode("utf8")
                        fingerprint = hashlib.sha256(encoded).digest()
                        repeated += fingerprint in feature_hashes
                        feature_hashes.add(fingerprint)
                        digest.update(encoded + b"\n")
                fingerprints[name] = feature_hashes
                results[name] = {"uncompressed_bytes": expected, "rows": rows,
                    "columns": columns, "declared_class_counts": dict(classes),
                    "event_code_counts": dict(events), "identity_format_counts": dict(identity),
                    "unique_feature_rows": len(feature_hashes), "repeated_feature_rows": repeated,
                    "canonical_feature_stream_sha256": digest.hexdigest()}
    train = fingerprints["fasttext-trainmodel.csv"]
    test = fingerprints["fasttext-testmodel.csv"]
    all_rows = fingerprints["fasttext-all-nofamily.csv"]
    return {"audit_version": 1, "audited_at_utc": datetime.now(timezone.utc).isoformat(),
        "purpose": "Benign Windows source suitability audit; no fitting or threshold calibration",
        "source": {"name": "SILRAD-1.0", "doi": "10.5281/zenodo.17104902",
            "record_url": "https://zenodo.org/records/17104902", "metadata_url": METADATA_URL,
            "archive_url": ARCHIVE_URL, "archive_bytes": len(raw),
            "publisher_checksum": "md5:" + ARCHIVE_MD5, "publisher_checksum_verified": True,
            "archive_sha256": hashlib.sha256(raw).hexdigest(),
            "publisher_declared_data_license": metadata["metadata"]["license"]["id"],
            "local_archive": archive.relative_to(ROOT).as_posix(),
            "nested_zip_sha256": hashlib.sha256(inner_raw).hexdigest(),
            "publisher_readme_sha256": hashlib.sha256(readme).hexdigest()},
        "publisher_collection_description": "Windows 11 VM Sysmon; benign games, apps and utilities; ransomware runs and goodware logs stitched together. Class 0=goodware, 1=ransomware. Labels are publisher claims, not independently verified.",
        "files": results,
        "split_audit": {"train_test_identical_feature_rows": len(train & test),
            "all_unique_features_equal_train_union_test": all_rows == train | test,
            "note": "Exact feature duplicates measure overlap, not process/campaign independence. Missing original times and run IDs prevent a trustworthy chronological/run split audit."},
        "deployment_fit": {"behavioral_training_eligible": False,
            "reason": "No timestamps or destination IP/port/protocol/connection-state fields. Identity columns do not preserve valid original GUIDs or integer PIDs. Cannot construct ordered process-scoped network sequences or distinguish SYN_SENT polling snapshots from established connections.",
            "raw_event_identity_verified": False,
            "excluded_from": ["runtime model fitting", "threshold selection", "malware accuracy estimates"],
            "potential_use": "Separate provenance-aware Sysmon categorical-feature research after validating identity transformations, labels and grouped splits; not this release's live network scorer."},
        "safety": {"downloaded_executables": 0, "executed_downloaded_code": False,
            "csvs_extracted": False, "telemetry_uploaded": False,
            "cache_location": "Ignored project training/data/v3/silrad on D:"}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--acquire", action="store_true", help="Fetch the 3.6 MB publisher feature release and metadata")
    args = parser.parse_args()
    if args.acquire:
        archive, metadata = acquire()
    else:
        archive = DATA / "publisher-release.zip"
        metadata = json.loads((DATA / "publisher-metadata.json").read_text(encoding="utf8"))
    result = audit(archive, metadata)
    MANIFEST.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf8", newline="\n")
    print(json.dumps({"manifest": MANIFEST.relative_to(ROOT).as_posix(),
        "all_rows": result["files"]["fasttext-all-nofamily.csv"]["rows"],
        "split_audit": result["split_audit"], "behavioral_training_eligible": False}))


if __name__ == "__main__":
    main()
