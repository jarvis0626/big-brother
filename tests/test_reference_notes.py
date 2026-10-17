"""Fabricated regressions for reference applicability, not malware accuracy tests."""
import json
from pathlib import Path

from backend.model import BehavioralModel, CONTEXT, event_token
from backend.service import Application

RESOURCES = Path(__file__).resolve().parents[1] / "resources"


def connection(index, port=443, status="ESTABLISHED"):
    return {"id": f"e{index}", "process_key": "fabricated:online", "pid": 1001,
            "timestamp": f"2026-10-17T05:00:{index:02d}Z", "kind": "network",
            "image": r"C:\Demo\arbitrary.exe", "source": "replay:test",
            "details": {"destination_port": port, "protocol": "tcp", "snapshot": True, "status": status}}


def test_warmup_has_no_short_context_score_and_first_target_uses_full_history():
    model = BehavioralModel(RESOURCES / "models")
    events = [connection(i) for i in range(CONTEXT)]
    short = model.score(events)
    assert short["status"] == "insufficient_context"
    assert short["score"] is None and not short["above_threshold"]
    events.append(connection(CONTEXT, 50001))
    complete = model.score(events)
    assert complete["status"] == "available"
    assert complete["score"] > complete["threshold"]
    assert complete["features"]["context_events"] == CONTEXT
    assert complete["evidence_event_ids"] == [event["id"] for event in events]
    assert complete["reference_context"]["preceding_category_counts"] == {"network_web": 16}


def test_pending_closing_tcp_snapshots_do_not_become_model_connections():
    model = BehavioralModel(RESOURCES / "models")
    events = [connection(i) for i in range(16)] + [connection(16, 50001)]
    baseline = model.score(events)
    closing = [connection(i + 17, 53000, status) for i, status in enumerate(("SYN_SENT", "CLOSE_WAIT", "FIN_WAIT1", "LAST_ACK"))]
    result = model.score(events + closing)
    assert result["score"] == baseline["score"]
    assert result["features"]["excluded_observation_reasons"] == {"non_established_tcp_snapshot": 4}
    assert all(event_token(event) is None for event in closing)
    assert event_token({"kind": "network", "details": {"destination_port": 53000, "protocol": "udp", "snapshot": True}}) is not None
    assert event_token({"kind": "network", "details": {"destination_port": 53000, "source": "sysmon"}}) is not None


def test_network_reference_keeps_score_citations_and_rules_separate(tmp_path):
    app = Application(RESOURCES, tmp_path, start_collector=False)
    try:
        sid = app.replay("network")["id"]
        state = app.state(sid)
        assert not state["incidents"] and len(state["behavior_notes"]) == 1
        note = state["behavior_notes"][0]
        assert note["classification"] == "reference_note" and note["severity"] == "info"
        assert note["score"] == state["model_assessment"]["score"] > state["model"]["threshold"]
        assert note["model_version"] == state["model"]["version"]
        assert set(note["event_ids"]) <= {event["id"] for event in state["events"]}
        assert all(not doc["id"].startswith("mitre-") for doc in note["explanation"]["documentation"])
        assert note["explanation"]["documentation"]
        exported = app.export(sid)
        assert exported["behavior_notes"] == state["behavior_notes"]
        assert exported["model_assessment"]["status"] == "reference_only"
        # An independent transparent rule must still surface beside the reference note.
        event = connection(30)
        event.update(process_key=state["session"]["root_key"], kind="registry", source_record_id="startup",
                     details={"target": r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Fabricated"})
        app.store.ingest(event)
        app.analyze(force=True, session_id=sid)
        assert len(app.state(sid)["incidents"]) == 1
        assert len(app.state(sid)["behavior_notes"]) == 1
    finally:
        app.close()


def test_historical_and_paused_sessions_are_reclassified_without_dropping_raw_events(tmp_path):
    app = Application(RESOURCES, tmp_path, start_collector=False)
    sid = app.replay("network")["id"]
    root_key = app.state(sid)["session"]["root_key"]
    extra = connection(31, 50009, "CLOSE_WAIT")
    extra.update(process_key=root_key, source_record_id="closing")
    app.store.ingest(extra)
    app.store.set_status(sid, "paused")
    # Simulate saved warnings written by the older application.
    app.store.save_incidents(sid, [{"id": "legacy", "session_id": sid, "title": "Legacy warning", "severity": "low"}])
    app.close()
    app = Application(RESOURCES, tmp_path, start_collector=False)
    try:
        state = app.state(sid)
        assert len(state["events"]) == 25
        assert not state["incidents"] and len(state["behavior_notes"]) == 1
        assert state["model_assessment"]["excluded_observation_reasons"] == {"non_established_tcp_snapshot": 1}
        # A clean shutdown stops paused sessions; test an actively paused session
        # after historical migration independently of that shutdown behavior.
        app.store.set_status(sid, "paused")
        def unexpected_rescore(events):
            raise AssertionError("A migrated paused session must remain paused")
        app.model.score = unexpected_rescore
        app.last_analysis = 0
        app.state(sid)
        assert app.last_model_error is None
    finally:
        app.close()


def test_no_game_name_or_specific_high_port_allowlist():
    model = BehavioralModel(RESOURCES / "models")
    events = [connection(i) for i in range(16)] + [connection(16, 50001)]
    baseline = model.score(events)
    for event in events:
        event["image"] = r"C:\Games\AoE2DE_s.exe"
        event["details"]["destination_ip"] = "192.0.2.99"
    events[-1]["details"]["destination_port"] = 60003
    assert model.score(events)["score"] == baseline["score"]
    active = json.loads((RESOURCES / "models/active.json").read_text())
    assert model.metadata["artifact_sha256"] == active["sha256"]
    assert model.metadata["threshold"] == active["threshold"]
