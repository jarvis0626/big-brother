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
    (tmp_path / "package.json").write_text(json.dumps({"version": "1.1.0"}))
    (tmp_path / "LICENSE").write_text("Example license")
    (tmp_path / "THIRD_PARTY_NOTICES.md").write_text("Example notices")
    config = release.release_config()
    for name in (config.installer, config.portable):
        (output / name).write_bytes(b"MZ" + name.encode())
    return output


def test_bundle_includes_both_exact_executables_and_excludes_private_files(workspace):
    config = release.release_config()
    (workspace / "private-history.sqlite3").write_bytes(b"must stay local")
    (workspace / "BigBrother-data").mkdir()
    (workspace / "BigBrother-data/user-data.txt").write_text("must stay local")
    manifest = release.build_bundle()
    with zipfile.ZipFile(workspace / config.bundle) as archive:
        assert len(archive.namelist()) == 6
        assert archive.read("Installer/" + config.installer) == (workspace / config.installer).read_bytes()
        assert archive.read("Portable/" + config.portable) == (workspace / config.portable).read_bytes()
        assert "private-history.sqlite3" not in "\n".join(archive.namelist())
        assert "fabricated" in archive.read("START-HERE.txt").decode()
        guide = archive.read("START-HERE.txt").decode()
        assert "BIG BROTHER 1.1.0" in guide and "/blob/v1.1.0/README.md" in guide
        assert "v1.0.0" not in guide
    assert release.verify_local() == manifest
    assert len(manifest["assets"]) == 4


def test_package_tampering_blocks_upload_before_network(workspace):
    release.build_bundle()
    (workspace / release.release_config().portable).write_bytes(b"MZchanged")
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
        release.upload_endpoint(url, 123, release.ReleaseConfig("1.1.0").bundle)


def test_github_sha_and_uploaded_state_required():
    row = {"name": release.ReleaseConfig("1.1.0").installer, "bytes": 123, "sha256": "a" * 64}
    valid = {"name": row["name"], "size": row["bytes"], "state": "uploaded", "digest": "sha256:" + row["sha256"]}
    release.verify_asset(valid, row)
    for change in [{"size": 0}, {"state": "starter"}, {"digest": None}, {"digest": "sha256:" + "b" * 64}]:
        with pytest.raises(release.CheckpointError, match="SHA256"):
            release.verify_asset({**valid, **change}, row)


def checked_source(monkeypatch, *, status="", tag_type="tag", remote_head=None,
                   remote_object=None, remote_commit=None):
    config = release.release_config()
    head, tag_object = "a" * 40, "b" * 40
    tag_ref = "refs/tags/" + config.tag
    calls = []

    def git(*args):
        calls.append(args)
        if args[0] == "status":
            assert args == ("status", "--porcelain", "--untracked-files=no")
            return SimpleNamespace(stdout=status)
        if args == ("rev-parse", "HEAD"):
            return SimpleNamespace(stdout=head)
        if args == ("cat-file", "-t", tag_ref):
            return SimpleNamespace(stdout=tag_type)
        if args == ("rev-parse", tag_ref):
            return SimpleNamespace(stdout=tag_object)
        if args == ("rev-parse", tag_ref + "^{}"):
            return SimpleNamespace(stdout=head)
        if args == ("ls-remote", "origin", "HEAD", tag_ref, tag_ref + "^{}"):
            rows = [(remote_head or head, "HEAD"), (remote_object or tag_object, tag_ref),
                    (remote_commit or head, tag_ref + "^{}")]
            return SimpleNamespace(stdout="\n".join(sha + "\t" + ref for sha, ref in rows))
        raise AssertionError("Unexpected git action")

    monkeypatch.setattr(release, "git", git)
    monkeypatch.setattr(release, "ensure_remote", lambda: None)
    return calls


def notes_file():
    notes = release.ROOT / "docs" / "releases" / (release.release_config().tag + ".md")
    notes.parent.mkdir(parents=True)
    notes.write_text("Reviewed notes")
    return notes


def test_incomplete_draft_cannot_be_published(workspace, monkeypatch):
    release.build_bundle()
    notes_file()
    checked_source(monkeypatch)
    class Client:
        def ensure_private(self): return None
        def request(self, method, path, *args, **kwargs):
            assert method != "PATCH", "Incomplete assets must block publication"
            if path.endswith("per_page=100"): return []
            return {"id": 123, "tag_name": release.release_config().tag, "draft": True, "body": "Reviewed notes"}
    monkeypatch.setattr(release, "GitHub", Client)
    with pytest.raises(release.CheckpointError, match="missing assets"):
        release.operate("publish")


def test_existing_draft_is_found_when_tag_endpoint_only_lists_published_releases(workspace):
    draft = {"id": 123, "tag_name": release.release_config().tag, "draft": True}
    class Client:
        def request(self, method, path, **kwargs):
            assert method == "GET"
            if "/releases/tags/" in path: return None
            return [draft]
    assert release.find_release(Client()) == draft


@pytest.mark.parametrize("version", ["0.2.0", "2.0.0", "1.01.0", "1.0.01", "1.1.0-beta.1",
                                     "1.1.0+build", "../v1.0.0", "1.0.0/../../private", None])
def test_only_stable_1x_package_versions_can_name_tags_and_notes(workspace, version):
    (release.ROOT / "package.json").write_text(json.dumps({"version": version}))
    with pytest.raises(release.CheckpointError, match="stable 1.x"):
        release.release_config()


def test_new_release_does_not_reuse_or_overwrite_prior_v1_packages(workspace):
    previous = release.ReleaseConfig("1.0.0")
    for name in (previous.installer, previous.portable, previous.bundle):
        (workspace / name).write_bytes(b"previous release remains intact")
    manifest = release.build_bundle()
    assert manifest["tag"] == "v1.1.0"
    assert all("1.1.0" in row["name"] or row["name"] == "SHA256SUMS.txt" for row in manifest["assets"])
    for name in (previous.installer, previous.portable, previous.bundle):
        assert (workspace / name).read_bytes() == b"previous release remains intact"
        with pytest.raises(release.CheckpointError, match="Unexpected release asset"):
            release.asset_path(name)


def test_version_is_read_at_operation_time_instead_of_module_import(workspace):
    assert release.release_config().tag == "v1.1.0"
    (release.ROOT / "package.json").write_text(json.dumps({"version": "1.2.3"}))
    assert release.release_config().tag == "v1.2.3"
    assert release.release_config().installer == "Big-Brother-1.2.3-x64-nsis.exe"


@pytest.mark.parametrize("status", [" M README.md\n", "M  README.md\n", "A  new-source.py\n"])
def test_tracked_or_staged_changes_block_release_before_network(workspace, monkeypatch, status):
    release.build_bundle()
    checked_source(monkeypatch, status=status)
    monkeypatch.setattr(release, "GitHub", lambda: pytest.fail("Dirty source must stop before network"))
    with pytest.raises(release.CheckpointError, match="Commit the reviewed source"):
        release.operate("draft")


@pytest.mark.parametrize("change", [
    {"tag_type": "commit"}, {"remote_head": "c" * 40},
    {"remote_object": "c" * 40}, {"remote_commit": "c" * 40},
])
def test_tag_must_be_annotated_and_match_exact_remote_object_head_and_commit(workspace, monkeypatch, change):
    release.build_bundle()
    checked_source(monkeypatch, **change)
    monkeypatch.setattr(release, "GitHub", lambda: pytest.fail("Unmatched source must stop before network"))
    with pytest.raises(release.CheckpointError, match="annotated"):
        release.operate("draft")


def release_client(manifest, *, tag=None, draft=True, body="Reviewed notes", assets=None, final_assets=None):
    assets = ([{"name": row["name"], "size": row["bytes"], "state": "uploaded",
                "digest": "sha256:" + row["sha256"], "browser_download_url": "https://github.com/example"}
               for row in manifest["assets"]] if assets is None else assets)
    entry = {"id": 123, "tag_name": tag or release.release_config().tag, "draft": draft, "body": body,
             "html_url": "https://github.com/jarvis0626/big-brother/releases/tag/" + release.release_config().tag}
    requests = []

    class Client:
        def ensure_private(self):
            requests.append(("PRIVATE", None))

        def request(self, method, path, *args, **kwargs):
            requests.append((method, path))
            if "/releases/tags/" in path:
                return dict(entry)
            if path.endswith("/assets?per_page=100"):
                return list(assets)
            if method == "PATCH":
                entry["draft"] = False
                return dict(entry)
            if method == "GET" and path.endswith("/releases/123"):
                return {**entry, "assets": list(assets if final_assets is None else final_assets)}
            raise AssertionError("Unexpected mocked GitHub operation")

    return Client, requests


def test_untracked_local_artwork_is_preserved_and_never_an_asset(workspace, monkeypatch):
    artwork = release.ROOT / "social-preview.png"
    artwork.write_bytes(b"unrelated user's artwork")
    manifest = release.build_bundle()
    notes_file()
    calls = checked_source(monkeypatch)
    client, requests = release_client(manifest)
    monkeypatch.setattr(release, "GitHub", client)
    result = release.operate("publish")
    assert result["tag"] == "v1.1.0" and result["draft"] is False
    assert artwork.read_bytes() == b"unrelated user's artwork"
    assert ("status", "--porcelain", "--untracked-files=no") in calls
    assert any(method == "PATCH" for method, _ in requests)
    assert all(row["name"] != "social-preview.png" for row in result["assets"])


@pytest.mark.parametrize("change", [
    {"tag": "v1.0.0"}, {"body": "Unreviewed notes"},
    {"assets": [{"name": "unrelated-user-file.txt"}]},
])
def test_unrelated_previous_or_unreviewed_release_is_preserved(workspace, monkeypatch, change):
    manifest = release.build_bundle()
    notes_file()
    checked_source(monkeypatch)
    client, requests = release_client(manifest, **change)
    monkeypatch.setattr(release, "GitHub", client)
    with pytest.raises(release.CheckpointError):
        release.operate("publish")
    assert not any(method in {"POST", "PATCH", "DELETE"} for method, _ in requests)


def test_private_repository_check_remains_mandatory(workspace, monkeypatch):
    release.build_bundle()
    notes_file()
    checked_source(monkeypatch)

    class PublicRepository:
        def ensure_private(self):
            raise release.CheckpointError("Destination is not verified private")

        def request(self, *args, **kwargs):
            pytest.fail("No release request may follow failed private verification")

    monkeypatch.setattr(release, "GitHub", PublicRepository)
    with pytest.raises(release.CheckpointError, match="private"):
        release.operate("draft")


def test_final_server_digest_is_checked_again_after_publication(workspace, monkeypatch):
    manifest = release.build_bundle()
    notes_file()
    checked_source(monkeypatch)
    tampered = [{"name": row["name"], "size": row["bytes"], "state": "uploaded", "digest": "sha256:" + "c" * 64}
                for row in manifest["assets"]]
    client, _ = release_client(manifest, final_assets=tampered)
    monkeypatch.setattr(release, "GitHub", client)
    with pytest.raises(release.CheckpointError, match="SHA256"):
        release.operate("publish")
