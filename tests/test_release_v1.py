"""Release boundaries: no unrelated local files or unverified published assets."""
import json
from pathlib import Path
from types import SimpleNamespace
import zipfile
import pytest
from scripts import release_v1 as release


@pytest.fixture
def workspace(tmp_path, monkeypatch):
    output = tmp_path / "release"
    output.mkdir()
    monkeypatch.setattr(release, "ROOT", tmp_path)
    monkeypatch.setattr(release, "RELEASE", output)
    (tmp_path / "package.json").write_text(json.dumps({"version": "1.0.0"}))
    (tmp_path / "LICENSE").write_text("Example license")
    (tmp_path / "THIRD_PARTY_NOTICES.md").write_text("Example notices")
    for name in (release.INSTALLER, release.PORTABLE):
        (output / name).write_bytes(b"MZ" + name.encode())
    return output


def test_bundle_includes_both_exact_executables_and_excludes_private_files(workspace):
    (workspace / "private-history.sqlite3").write_bytes(b"must stay local")
    (workspace / "BigBrother-data").mkdir()
    (workspace / "BigBrother-data/user-data.txt").write_text("must stay local")
    manifest = release.build_bundle()
    with zipfile.ZipFile(workspace / release.BUNDLE) as archive:
        assert len(archive.namelist()) == 6
        assert archive.read("Installer/" + release.INSTALLER) == (workspace / release.INSTALLER).read_bytes()
        assert archive.read("Portable/" + release.PORTABLE) == (workspace / release.PORTABLE).read_bytes()
        assert "private-history.sqlite3" not in "\n".join(archive.namelist())
        assert "fabricated" in archive.read("START-HERE.txt").decode()
    assert release.verify_local() == manifest
    assert len(manifest["assets"]) == 4


def test_package_tampering_blocks_upload_before_network(workspace):
    release.build_bundle()
    (workspace / release.PORTABLE).write_bytes(b"MZchanged")
    with pytest.raises(release.CheckpointError, match="changed"):
        release.verify_local()


@pytest.mark.parametrize("url", [
    "http://uploads.github.com/repos/jarvis0626/big-brother/releases/123/assets",
    "https://uploads.github.com.evil.example/repos/jarvis0626/big-brother/releases/123/assets",
    "https://user@uploads.github.com/repos/jarvis0626/big-brother/releases/123/assets",
    "https://uploads.github.com/repos/other/repo/releases/123/assets",
    "https://uploads.github.com/repos/jarvis0626/big-brother/releases/456/assets",
    "https://uploads.github.com/repos/jarvis0626/big-brother/releases/123/assets?extra=value",
])
def test_upload_never_sends_credentials_to_unexpected_endpoint(url):
    with pytest.raises(release.CheckpointError, match="destination"):
        release.upload_endpoint(url, 123, release.BUNDLE)


def test_github_sha_and_uploaded_state_required():
    row = {"name": release.INSTALLER, "bytes": 123, "sha256": "a" * 64}
    valid = {"name": row["name"], "size": row["bytes"], "state": "uploaded", "digest": "sha256:" + row["sha256"]}
    release.verify_asset(valid, row)
    for change in [{"size": 0}, {"state": "starter"}, {"digest": None}, {"digest": "sha256:" + "b" * 64}]:
        with pytest.raises(release.CheckpointError, match="SHA256"):
            release.verify_asset({**valid, **change}, row)


def test_incomplete_draft_cannot_be_published(workspace, monkeypatch):
    release.build_bundle()
    notes = release.ROOT / "docs/releases/v1.0.0.md"
    notes.parent.mkdir(parents=True)
    notes.write_text("Reviewed notes")
    def git(*args):
        if args[0] == "status": return SimpleNamespace(stdout="")
        return SimpleNamespace(stdout="a" * 40)
    monkeypatch.setattr(release, "git", git)
    monkeypatch.setattr(release, "ensure_remote", lambda: None)
    class Client:
        def ensure_private(self): return None
        def request(self, method, path, *args, **kwargs):
            assert method != "PATCH", "Incomplete assets must block publication"
            if path.endswith("per_page=100"): return []
            return {"id": 123, "draft": True, "body": "Reviewed notes"}
    monkeypatch.setattr(release, "GitHub", Client)
    with pytest.raises(release.CheckpointError, match="missing assets"):
        release.operate("publish")


def test_existing_draft_is_found_when_tag_endpoint_only_lists_published_releases():
    draft = {"id": 123, "tag_name": release.TAG, "draft": True}
    class Client:
        def request(self, method, path, **kwargs):
            assert method == "GET"
            if "/releases/tags/" in path: return None
            return [draft]
    assert release.find_release(Client()) == draft
