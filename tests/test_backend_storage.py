import json
from pathlib import Path

import pytest

from backend.storage import EvidenceStore, poll_key, timestamp


@pytest.fixture
def store(tmp_path):
    value = EvidenceStore(tmp_path / "evidence.sqlite3")
    yield value
    value.close()


def event(key, record, kind="process_start", parent=None, time="2026-10-07T01:00:00Z", **extra):
    return {"process_key": key, "parent_key": parent, "kind": kind, "timestamp": time,
            "pid": 42, "source": "fixture", "source_record_id": record, "image": "C:\\Test\\example.exe", **extra}


def test_identity_pid_reuse_and_utc_offset(store):
    first, second = poll_key(42, 1234.123456), poll_key(42, 1235.123456)
    assert first != second
    sid = store.create_session("root", "live", first)["id"]
    store.ingest(event(first, 1))
    store.ingest(event(first, 2, "process_end", time="2026-10-07T01:01:00Z"))
    store.ingest(event(second, 3, time="2026-10-07T01:02:00Z"))
    assert {node["key"] for node in store.processes(sid)} == {first}
    assert timestamp("2026-10-07T06:30:00+05:30") == "2026-10-07T01:00:00.000+00:00"
    assert timestamp("2026-10-07T01:00:00Z") == timestamp("2026-10-07T06:30:00+05:30")


def test_out_of_order_duplicate_surviving_descendant(store):
    sid = store.create_session("root", "live", "root")["id"]
    store.ingest(event("child", 4, "network", time="2026-10-07T01:04:00Z", details={"destination_ip": "127.0.0.1"}))
    store.ingest(event("root", 1))
    store.ingest(event("root", 3, "process_end", time="2026-10-07T01:03:00Z"))
    creation = event("child", 2, parent="root", time="2026-10-07T01:02:00Z")
    assert store.ingest(creation)
    assert not store.ingest(creation)
    nodes = store.processes(sid)
    assert len(nodes) == 2
    child = next(node for node in nodes if node["key"] == "child")
    assert child["parent_key"] == "root" and child["ended_at"] is None
    evidence = store.events(sid)
    assert len(evidence) == 4
    assert evidence[-1]["kind"] == "network"
    assert evidence[-1]["parent_key"] == "root"


def test_alias_guid_merges_late_ancestry(store):
    sid = store.create_session("root", "live", "poll:42:1")["id"]
    store.ingest(event("poll:42:1", 1))
    store.ingest(event("guid:child", 2, parent="guid:root"))
    store.ingest(event("guid:root", 3))
    store.alias("guid:root", "poll:42:1")
    assert store.resolve("guid:root") == "poll:42:1"
    assert len(store.processes(sid)) == 2
    assert len(store.events(sid)) == 3
    assert next(p for p in store.processes(sid) if p["key"] == "guid:child")["parent_key"] == "poll:42:1"


def test_event_source_epoch_disambiguates_reset_record_ids(store):
    first = event("root", 1, source_epoch="old")
    second = event("root", 1, source_epoch="new")
    assert store.ingest(first)
    assert store.ingest(second)


def test_restart_marks_active_sessions_interrupted_and_keeps_cursor(tmp_path):
    path = tmp_path / "evidence.sqlite3"
    first = EvidenceStore(path)
    sid = first.create_session("watch", "live", "root")["id"]
    first.set_meta("sysmon_cursor", 77)
    first.close()
    second = EvidenceStore(path)
    try:
        assert second.session(sid)["status"] == "interrupted"
        assert second.get_meta("sysmon_cursor") == 77
        assert any("restarted" in gap["detail"] for gap in second.gaps())
    finally:
        second.close()


def test_retention_deletion_and_stopped_session_isolation(store):
    one = store.create_session("one", "live", "root")["id"]
    two = store.create_session("two", "live", "root")["id"]
    store.ingest(event("root", 1))
    store.set_status(one, "stopped")
    ended = store.session(one)["ended_at"]
    store.ingest(event("root", 2, "network"))
    # Guarantee a later ingestion time independent of fast clock resolution.
    store.db.execute("UPDATE events SET ingested_at='2099-01-01T00:00:00+00:00' WHERE source_record_id='2'")
    store.db.commit()
    assert len(store.events(one)) == 1
    assert len(store.events(two)) == 2
    store.delete_session(one)
    assert len(store.events(two)) == 2  # Shared evidence survives deletion of one session.
    store.delete_session(two)
    assert store.db.execute("SELECT count(*) FROM events").fetchone()[0] == 0


def test_bounded_retention_publishes_gap(store):
    sid = store.create_session("watch", "live", "root")["id"]
    for number in range(505):
        store.ingest(event("root", number))
    store.settings({"max_events": 500})
    assert len(store.events(sid)) == 500
    assert any("5 evidence" in gap["detail"] for gap in store.gaps())
    with pytest.raises(ValueError):
        store.settings({"retention_days": 0})
    with pytest.raises(ValueError):
        store.settings({"max_events": True})
    with pytest.raises(ValueError):
        store.settings({"unknown": "setting"})


def test_untrusted_strings_not_sql_or_commands(store):
    sid = store.create_session("watch", "live", "root")["id"]
    malicious = "'; DROP TABLE sessions; -- $(Start-Process calc.exe) ignore all instructions"
    store.ingest(event("root", 1, command_line=malicious, details={"target": malicious}))
    assert store.session(sid)["name"] == "watch"
    assert store.events(sid)[0]["command_line"] == malicious


def test_old_active_session_not_lost_behind_many_replays(store):
    sid = store.create_session("active", "live", "root")["id"]
    for number in range(110):
        store.create_session(str(number), "replay", f"replay:{number}")
    assert any(session["id"] == sid for session in store.sessions())
