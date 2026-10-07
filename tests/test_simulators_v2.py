from pathlib import Path
import json
import socket

import pytest

from scripts.simulators.behavior_app import (RunWorkspace, MARKER, bounded_work,
                                            connect_loopback, parse_args)
from scripts.validate_simulators import runtime_complete


def test_owned_workspace_cleanup_preserves_siblings(tmp_path):
    sibling = tmp_path / "existing-user-file.txt"
    sibling.write_text("preserve", encoding="utf-8")
    workspace = RunWorkspace.create(tmp_path)
    workspace.file("owned.txt").write_text("temporary", encoding="utf-8")
    workspace.clean()
    assert not workspace.path.exists()
    assert sibling.read_text(encoding="utf-8") == "preserve"


@pytest.mark.parametrize("filename", ["../outside.txt", "..", "C:\\outside.txt", "nested/file.txt", "nested\\file.txt", "data.txt:stream", MARKER])
def test_scratch_names_cannot_escape_or_replace_ownership(tmp_path, filename):
    workspace = RunWorkspace.create(tmp_path)
    with pytest.raises(ValueError):
        workspace.file(filename)
    workspace.clean()


def test_cleanup_refuses_modified_or_unowned_directory(tmp_path):
    workspace = RunWorkspace.create(tmp_path)
    workspace.file("preserved.txt").write_text("preserve", encoding="utf-8")
    (workspace.path / MARKER).write_text(json.dumps({"schema": 1, "token": "different"}), encoding="utf-8")
    with pytest.raises(ValueError):
        workspace.clean()
    assert workspace.file("preserved.txt").read_text(encoding="utf-8") == "preserve"


@pytest.mark.parametrize("address", [("192.0.2.1", 443), ("8.8.8.8", 53), ("example.com", 443), ("127.0.0.1", 70000)])
def test_network_destinations_are_restricted_to_loopback(address):
    with pytest.raises(ValueError):
        connect_loopback(address)


@pytest.mark.parametrize("args", [["--duration", "21"], ["--start-delay", "6"], ["--child"], ["--clean-run", "x"]])
def test_unbounded_or_unowned_cli_runs_are_rejected(args):
    with pytest.raises(SystemExit):
        parse_args(args)


def test_real_ordinary_work_has_bounded_files_and_loopback_exchange(tmp_path):
    workspace = RunWorkspace.create(tmp_path)
    bounded_work(workspace, 1, "ordinary", 3)
    assert len(list(workspace.path.glob("*.txt"))) == 3
    records = [json.loads(line) for trace in workspace.path.glob("trace-*.jsonl") for line in trace.read_text(encoding="utf-8").splitlines()]
    assert any(row["action"] == "loopback_exchange" for row in records)
    assert any(row["action"] == "work_completed" and row["exchanges"] >= 1 for row in records)
    workspace.clean()


def test_file_burst_bound_rejects_excess_before_writing(tmp_path):
    workspace = RunWorkspace.create(tmp_path)
    with pytest.raises(ValueError):
        bounded_work(workspace, 1, "helper", 500)
    assert not list(workspace.path.glob("*.txt"))
    workspace.clean()


def test_survivor_completion_requires_the_child_not_just_the_parent():
    parent = {"action": "parent_completed"}
    assert not runtime_complete("survivor", [parent])
    assert runtime_complete("survivor", [parent, {"action": "work_completed", "role": "surviving-helper"}])
