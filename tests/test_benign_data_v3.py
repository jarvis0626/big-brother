"""Acquisition guards and exclusion semantics for inert public feature data."""
import hashlib
import io
import zipfile

import pytest

from training import audit_benign_v3 as audit


def fixture_archive(tmp_path, monkeypatch, extra=None):
    # Fabricated CSVs test audit behavior; they never become training evidence.
    header = "event.code,ProcessGuid,ProcessId,class\n"
    row = "3,{12345678-1234-1234-1234-123456789abc},42,0\n"
    payloads = {name: (header + row).encode() for name in audit.CSV_BYTES}
    inner = io.BytesIO()
    with zipfile.ZipFile(inner, "w") as container:
        for name, value in payloads.items():
            container.writestr(name, value)
    outer = io.BytesIO()
    with zipfile.ZipFile(outer, "w") as container:
        container.writestr(audit.PREFIX + "README.md", "Synthetic unit-test provenance.")
        container.writestr(audit.PREFIX + "SILRAD-dataset.zip", inner.getvalue())
        if extra:
            container.writestr(extra, "Inert unexpected member.")
    raw = outer.getvalue()
    monkeypatch.setattr(audit, "ARCHIVE_BYTES", len(raw))
    monkeypatch.setattr(audit, "ARCHIVE_MD5", hashlib.md5(raw).hexdigest())
    monkeypatch.setattr(audit, "CSV_BYTES", {name: len(value) for name, value in payloads.items()})
    monkeypatch.setattr(audit, "DATA", tmp_path)
    monkeypatch.setattr(audit, "ROOT", tmp_path)
    path = tmp_path / "release.zip"
    path.write_bytes(raw)
    return path


def test_overlapping_features_are_reported_and_missing_network_schema_stays_excluded(tmp_path, monkeypatch):
    archive = fixture_archive(tmp_path, monkeypatch)
    result = audit.audit(archive, {"metadata": {"license": {"id": "cc-by-4.0"}}})
    assert result["split_audit"]["train_test_identical_feature_rows"] == 1
    assert result["deployment_fit"]["behavioral_training_eligible"] is False
    assert result["files"]["fasttext-all-nofamily.csv"]["identity_format_counts"]["ProcessGuid_valid_guid"] == 1
    assert not list(tmp_path.glob("*.csv"))


@pytest.mark.parametrize("extra", ["unexpected.exe", "../outside.txt"])
def test_unlisted_and_traversal_members_are_rejected_before_extracting(tmp_path, monkeypatch, extra):
    archive = fixture_archive(tmp_path, monkeypatch, extra)
    with pytest.raises(ValueError, match="Unexpected publisher release members"):
        audit.audit(archive, {"metadata": {"license": {"id": "cc-by-4.0"}}})
    assert not (tmp_path / "publisher-README.md").exists()


def test_corrupt_release_rejected_before_zip_parsing(tmp_path, monkeypatch):
    archive = fixture_archive(tmp_path, monkeypatch)
    raw = archive.read_bytes()
    archive.write_bytes(bytes([raw[0] ^ 1]) + raw[1:])
    with pytest.raises(ValueError, match="MD5 mismatch"):
        audit.audit(archive, {"metadata": {"license": {"id": "cc-by-4.0"}}})
