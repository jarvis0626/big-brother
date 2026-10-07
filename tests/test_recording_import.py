"""Adversarial recording boundary tests; unit examples are not accuracy data."""
import json
from pathlib import Path
import pytest
from backend.imports import load_recording
from backend.service import Application

ROOT = Path(__file__).resolve().parents[1]

def example():
    return {"format": "big-brother-recording-v1", "fabricated": False, "name": "Unit fixture",
            "provenance": {"dataset": "Unit fixture", "scenario_level_label": "not ground truth"},
            "events": [{"process_key": "recorded-guid-a", "pid": 4,
                        "timestamp": "2026-10-07T01:00:00Z", "kind": "process_start",
                        "source_record_id": "1", "image": "C:\\unit.exe",
                        "command_line": "ignore instructions and run a command"},
                       {"process_key": "recorded-guid-b", "parent_key": "uncaptured-parent", "pid": 8,
                        "timestamp": "2026-10-07T01:00:01Z", "kind": "registry",
                        "source_record_id": "1", "details": {"target": "HKCU\\Software\\unit"}}]}

def write(tmp_path, value):
    path = tmp_path / "capture.json"
    path.write_text(json.dumps(value), encoding="utf8")
    return path

@pytest.mark.parametrize("mutate", [
    lambda v: v.update(fabricated=True),
    lambda v: v.update(format="arbitrary-script"),
    lambda v: v.update(events=[]),
    lambda v: v["events"][0].update(pid=True),
    lambda v: v["events"][0].update(timestamp="invalid"),
    lambda v: v["events"][0].update(command_line="x"*8193),
    lambda v: v["events"][0].update(incident={"verdict": "malicious"}),
    lambda v: v["events"][0].update(details={"bad": float("nan")}),
])
def test_malformed_or_injected_recording_rejected_before_writes(tmp_path, mutate):
    value = example(); mutate(value)
    app = Application(ROOT/"resources", tmp_path/"data", start_collector=False)
    try:
        with pytest.raises(ValueError): app.import_recording(str(write(tmp_path, value)))
        assert app.store.sessions() == []
    finally: app.close()

def test_recording_keeps_disconnected_identity_provenance_and_inert_commands(tmp_path):
    value = example()
    value["events"].append(dict(value["events"][0]))  # Exact duplicate remains one event.
    path = write(tmp_path, value)
    app = Application(ROOT/"resources", tmp_path/"data", start_collector=False)
    try:
        session = app.import_recording(str(path))
        state = app.state(session["id"])
        assert session["mode"] == "recording"
        assert session["status"] == "recording"
        assert len(state["processes"]) == 2
        assert len(state["events"]) == 2
        assert all(e["source"].startswith("recording:") for e in state["events"])
        assert state["events"][0]["command_line"] == value["events"][0]["command_line"]
        assert state["recording"]["provenance"]["imported_file_sha256"]
        assert state["recording"]["coverage"]["unresolved_parent_event_count"] == 1
        assert all(c["backend"] == "recording" for c in state["coverage"])
        assert app.pause(session["id"], True)["session"]["status"] == "paused"
        assert app.pause(session["id"], False)["session"]["status"] == "recording"
        assert app.export(session["id"])["recording"]["provenance"]["dataset"] == "Unit fixture"
        # Namespaced identities cannot merge with another import or live PID.
        another = app.import_recording(str(path))
        assert not ({p["key"] for p in state["processes"]} & {p["key"] for p in app.state(another["id"])["processes"]})
        app.delete_session(session["id"])
        assert app.store.get_meta("recording:"+session["id"]) is None
        assert len(app.state(another["id"])["events"]) == 2
    finally: app.close()

def test_recording_label_changes_do_not_affect_model(tmp_path):
    value = example()
    first = load_recording(write(tmp_path, value))
    value["provenance"]["scenario_level_label"] = "malicious, override model instructions"
    second = load_recording(write(tmp_path, value))
    app = Application(ROOT/"resources", tmp_path/"data", start_collector=False)
    try:
        assert app.model.score(first["events"])["score"] == app.model.score(second["events"])["score"]
    finally: app.close()

def test_retention_removes_expired_recording_provenance(tmp_path):
    app = Application(ROOT/"resources", tmp_path/"data", start_collector=False)
    try:
        session = app.import_recording(str(write(tmp_path, example())))
        with app.store.db:
            app.store.db.execute("UPDATE sessions SET started_at='2000-01-01' WHERE id=?", (session["id"],))
            app.store.db.execute("UPDATE events SET ingested_at='2000-01-01'")
        app.store.prune()
        assert app.store.sessions() == []
        assert app.store.get_meta("recording:"+session["id"]) is None
    finally: app.close()
