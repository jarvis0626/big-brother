"""Private-push guardrails without network calls or credentials."""
from pathlib import Path
from types import SimpleNamespace
import json

import pytest

from scripts import github_milestone as milestone


def client_with(repository):
    client = milestone.GitHub.__new__(milestone.GitHub)
    client.request = lambda *args, **kwargs: repository
    return client


def test_public_repository_is_rejected_before_push():
    client = client_with({"private": False, "visibility": "public", "full_name": "jarvis0626/big-brother", "permissions": {"push": True}})
    with pytest.raises(milestone.CheckpointError, match="not verified private"):
        client.ensure_private()


def test_repository_owner_and_push_permission_are_checked():
    client = client_with({"private": True, "visibility": "private", "full_name": "another-user/big-brother", "permissions": {"push": True}})
    with pytest.raises(milestone.CheckpointError, match="identity"):
        client.ensure_private()
    client = client_with({"private": True, "visibility": "private", "full_name": "jarvis0626/big-brother", "permissions": {"push": False}})
    with pytest.raises(milestone.CheckpointError, match="push permission"):
        client.ensure_private()


def test_existing_different_origin_is_preserved(monkeypatch):
    calls = []
    def fake_git(*args, **kwargs):
        calls.append(args)
        return SimpleNamespace(returncode=0, stdout="https://github.com/another/repo.git\n")
    monkeypatch.setattr(milestone, "git", fake_git)
    with pytest.raises(milestone.CheckpointError, match="preserved"):
        milestone.ensure_remote()
    assert calls == [("remote", "get-url", "origin")]


def test_raw_data_and_credentials_refused_without_logging_contents(tmp_path, monkeypatch):
    monkeypatch.setattr(milestone, "ROOT", tmp_path)
    target = tmp_path / "training" / "data" / "raw.txt"
    target.parent.mkdir(parents=True)
    target.write_text("raw telemetry")
    monkeypatch.setattr(milestone, "git", lambda *args, **kwargs: SimpleNamespace(stdout="training/data/raw.txt\0", returncode=0))
    with pytest.raises(milestone.CheckpointError, match="Raw data"):
        milestone.audit_paths()
    key = tmp_path / "accidental.txt"
    key.write_text("-----BEGIN " + "PRIVATE KEY-----\nplaceholder\n-----END " + "PRIVATE KEY-----")
    monkeypatch.setattr(milestone, "git", lambda *args, **kwargs: SimpleNamespace(stdout="accidental.txt\0", returncode=0))
    with pytest.raises(milestone.CheckpointError) as error:
        milestone.audit_paths()
    assert "credential material" in str(error.value)
    assert "BEGIN PRIVATE KEY" not in str(error.value)


def test_push_rechecks_private_and_verifies_sha_without_force(monkeypatch):
    calls, privacy = [], []
    client = SimpleNamespace(ensure_private=lambda: privacy.append(True))
    monkeypatch.setattr(milestone, "ensure_remote", lambda: None)
    monkeypatch.setattr(milestone, "audit_paths", lambda: {"candidate_files": 2, "candidate_bytes": 100})
    sha = "a" * 40
    def fake_git(*args, **kwargs):
        calls.append(args)
        if args[:3] == ("diff", "--cached", "--quiet"):
            return SimpleNamespace(returncode=1, stdout="")
        if args[0] == "rev-parse":
            return SimpleNamespace(returncode=0, stdout=sha)
        if args[0] == "branch":
            return SimpleNamespace(returncode=0, stdout="main")
        if args[0] == "ls-remote":
            return SimpleNamespace(returncode=0, stdout=f"{sha}\trefs/heads/main\n")
        return SimpleNamespace(returncode=0, stdout="")
    monkeypatch.setattr(milestone, "git", fake_git)
    result = milestone.checkpoint(client, "Tested milestone")
    assert len(privacy) == 2
    assert ("push", "--set-upstream", "origin", "main:main") in calls
    assert all("--force" not in call for call in calls)
    assert result["verified_remote_commit"] == sha


@pytest.fixture
def isolated_repository(tmp_path, monkeypatch):
    monkeypatch.setattr(milestone, "ROOT", tmp_path)
    milestone.git("init", "--initial-branch=main")
    milestone.git("config", "user.name", "Checkpoint test")
    milestone.git("config", "user.email", "checkpoint@example.invalid")
    milestone.git("config", "commit.gpgsign", "false")
    milestone.git("config", "core.autocrlf", "false")
    milestone.git("config", "core.hooksPath", str(tmp_path / "disabled-hooks"))
    source = tmp_path / "source.py"
    source.write_bytes(b"value = 1\n")
    milestone.git("add", "source.py")
    milestone.git("commit", "-m", "Initial test source")
    return source


def test_staged_checkpoint_preserves_unrelated_untracked_file_and_unstaged_edits(isolated_repository, monkeypatch):
    source = isolated_repository
    source.write_bytes(b"value = 2\n")
    milestone.git("add", "source.py")
    source.write_bytes(b"value = 3\n")
    preview = milestone.ROOT / "social-preview.png"
    preview.write_bytes(b"Unrelated user preview; preserve exactly.")
    real_git = milestone.git
    calls = []
    def local_only_git(*args, **kwargs):
        calls.append(args)
        if args[0] == "push":
            return SimpleNamespace(returncode=0, stdout="")
        if args[0] == "ls-remote":
            sha = real_git("rev-parse", "HEAD").stdout.strip()
            return SimpleNamespace(returncode=0, stdout=f"{sha}\trefs/heads/main\n")
        return real_git(*args, **kwargs)
    monkeypatch.setattr(milestone, "git", local_only_git)
    monkeypatch.setattr(milestone, "ensure_remote", lambda: None)
    client = SimpleNamespace(ensure_private=lambda: None)
    result = milestone.checkpoint(client, "Only reviewed index content", staged_only=True)
    assert result["candidate_files"] == 1
    assert real_git("show", "HEAD:source.py", binary=True).stdout == b"value = 2\n"
    assert source.read_bytes() == b"value = 3\n"
    assert preview.read_bytes() == b"Unrelated user preview; preserve exactly."
    assert real_git("ls-files", "--", "social-preview.png").stdout == ""
    assert "?? social-preview.png" in real_git("status", "--porcelain").stdout
    assert not any(call[0] == "add" for call in calls)
    assert ("push", "--set-upstream", "origin", "main:main") in calls


def test_index_credential_is_caught_even_when_worktree_copy_is_clean(isolated_repository):
    source = isolated_repository
    source.write_text("-----BEGIN " + "PRIVATE KEY-----\nsynthetic test marker\n", encoding="utf8")
    milestone.git("add", "source.py")
    source.write_bytes(b"value = 1\n")
    with pytest.raises(milestone.CheckpointError, match="credential material"):
        milestone.audit_paths(staged_only=True)
    # The default still audits worktree candidates exactly as before.
    assert milestone.audit_paths()["candidate_files"] == 1


def test_staged_audit_uses_safe_index_and_ignores_untracked_sensitive_files(isolated_repository, monkeypatch, capsys):
    source = isolated_repository
    staged_size = len(source.read_bytes())
    source.write_text("-----BEGIN " + "PRIVATE KEY-----\nsynthetic unstaged marker\n", encoding="utf8")
    (milestone.ROOT / "local.sqlite3").write_bytes(b"Untracked local data.")
    monkeypatch.setattr(milestone.sys, "argv", ["github_milestone.py", "--audit", "--staged-only"])
    monkeypatch.setattr(milestone, "GitHub", lambda: pytest.fail("Local audit must not authenticate or call GitHub"))
    assert milestone.main() == 0
    assert json.loads(capsys.readouterr().out) == {"candidate_files": 1, "candidate_bytes": staged_size}
    with pytest.raises(milestone.CheckpointError, match="Sensitive local data|credential material"):
        milestone.audit_paths()
