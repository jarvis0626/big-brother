"""Private-push guardrails without network calls or credentials."""
from pathlib import Path
from types import SimpleNamespace

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
