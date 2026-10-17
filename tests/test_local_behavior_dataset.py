"""Privacy and holdout guards for explicit local diagnostic captures."""
import json
from pathlib import Path
import sqlite3
from types import SimpleNamespace

import pytest

from scripts import local_behavior_dataset as dataset


SELECTED = "session_private_diagnostic"
OTHER = "session_unselected_private"
PRIVATE = "PRIVATE_SENTINEL_NEVER_EXPORT"


@pytest.fixture
def local_store(tmp_path, monkeypatch):
    project = tmp_path / "project"
    project.mkdir()
    monkeypatch.setattr(dataset, "ROOT", project)
    path = tmp_path / "evidence.sqlite3"
    with sqlite3.connect(path) as db:
        db.executescript("""
            CREATE TABLE sessions(id TEXT PRIMARY KEY,mode TEXT,ended_at TEXT);
            CREATE TABLE membership(session_id TEXT,process_key TEXT);
            CREATE TABLE processes(key TEXT,parent_key TEXT,name TEXT,image TEXT,command_line TEXT,pid INT);
            CREATE TABLE events(id TEXT,process_key TEXT,parent_key TEXT,kind TEXT,details TEXT,
                source TEXT,uncertain INT,timestamp TEXT,image TEXT,command_line TEXT,pid INT,ingested_at TEXT);
        """)
        db.executemany("INSERT INTO sessions(id,mode) VALUES(?,?)", [(SELECTED, "live"), (OTHER, "live")])
        for key, parent in [(PRIVATE + "_root_guid", PRIVATE + "_uncaptured_parent"),
                            (PRIVATE + "_child_guid", PRIVATE + "_root_guid")]:
            db.execute("INSERT INTO membership VALUES(?,?)", (SELECTED, key))
            db.execute("INSERT INTO processes VALUES(?,?,?,?,?,?)",
                       (key, parent, PRIVATE, "C:/Users/" + PRIVATE + "/game.exe", PRIVATE, 45991))
        rows = [
            ("process_start", PRIVATE + "_root_guid", PRIVATE + "_uncaptured_parent", {}, "polling"),
            ("network", PRIVATE + "_root_guid", None,
             {"destination_ip": "203.0.113.99", "local_ip": "192.0.2.99", "destination_port": 443,
              "local_port": 45991, "dns": PRIVATE + ".example", "protocol": "tcp", "status": "ESTABLISHED",
              "snapshot": True, "extra": PRIVATE}, "polling"),
            ("dns", PRIVATE + "_child_guid", PRIVATE + "_root_guid",
             {"query": PRIVATE + ".example", "answer": "203.0.113.99", "snapshot": True}, "sysmon"),
            ("network", PRIVATE + "_child_guid", None,
             {"destination_port": 54321, "protocol": "udp", "status": PRIVATE,
              "TargetImage": PRIVATE, "snapshot": PRIVATE}, "recording:" + PRIVATE),
            ("network", PRIVATE + "_root_guid", None,
             {"destination_port": PRIVATE, "protocol": PRIVATE, "status": PRIVATE}, PRIVATE),
        ]
        for index, (kind, key, parent, details, source) in enumerate(rows):
            db.execute("INSERT INTO events VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                       (PRIVATE + str(index), key, parent, kind, json.dumps(details), source, 1,
                        f"2026-10-17T01:02:0{index}Z", PRIVATE, PRIVATE, 45991,
                        f"2026-10-17T01:02:0{index}Z"))
        db.execute("INSERT INTO processes VALUES(?,?,?,?,?,?)", ("other_key", None, PRIVATE, PRIVATE, PRIVATE, 1))
        db.execute("INSERT INTO membership VALUES(?,?)", (OTHER, "other_key"))
        db.execute("INSERT INTO events VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                   ("other_event", "other_key", None, "unsupported_unselected_kind", "not json", PRIVATE,
                    1, "2000-01-01", PRIVATE, PRIVATE, 1, "2000-01-01"))
    return path, project / "training" / "data" / "v3" / "local"


def read_only_output(directory):
    files = list(directory.glob("*.json"))
    assert len(files) == 1
    text = files[0].read_text(encoding="utf-8")
    return text, json.loads(text)


def test_export_is_selected_read_only_and_excludes_all_raw_identifiers(local_store, capsys, monkeypatch):
    database, output = local_store
    before = database.read_bytes()
    real_connect = sqlite3.connect
    connections = []

    def traced_connect(path, **kwargs):
        assert kwargs["uri"] is True and path.endswith("?mode=ro")
        connection = real_connect(path, **kwargs)
        connections.append(connection)
        return connection

    monkeypatch.setattr(dataset.sqlite3, "connect", traced_connect)
    summary = dataset.export_local_holdout(database, SELECTED)
    assert summary["events"] == 5 and summary["processes"] == 2
    assert summary["privacy_schema_passed"] is True
    assert summary["raw_identifiers_exported"] is False
    assert database.read_bytes() == before
    assert capsys.readouterr().out == ""
    text, value = read_only_output(output)
    for forbidden in [PRIVATE, SELECTED, OTHER, "203.0.113.99", "192.0.2.99", "45991", "54321",
                      "2026-10-17", "timestamp", "command_line", "image", "source_record_id", "pid", "guid"]:
        assert forbidden not in text
    assert [e["order"] for e in value["events"]] == list(range(5))
    assert value["events"][1]["destination_port_category"] == "web"
    assert value["events"][1]["tcp_status"] == "ESTABLISHED"
    assert value["events"][3]["protocol"] == "udp"
    assert value["events"][3]["tcp_status"] == "NOT_APPLICABLE"
    assert value["events"][3]["source"] == "recording"
    assert value["events"][3]["snapshot"] is False
    assert value["events"][4]["protocol"] == "unknown"
    assert value["events"][4]["tcp_status"] == "UNKNOWN"
    assert value["events"][4]["source"] == "unknown"
    assert value["processes"] == [{"identity": "p1", "parent": None}, {"identity": "p2", "parent": "p1"}]
    assert value["role"] == "diagnostic_holdout"
    assert value["label"] == "user_reported_expected"
    assert value["fit_eligible"] is False and value["calibration_eligible"] is False
    assert value["automatic_upload"] is False
    # The selected-only queries never parse the other session's malformed data.
    assert value["events"][0]["kind"] == "process_start"


def test_stopped_session_excludes_later_evidence_for_process_watched_again(local_store):
    database, output = local_store
    with sqlite3.connect(database) as db:
        db.execute("UPDATE sessions SET ended_at=? WHERE id=?", ("2026-10-17T01:02:05Z", SELECTED))
        db.execute("INSERT INTO membership VALUES(?,?)", (OTHER, PRIVATE + "_root_guid"))
        # The later observation describes an older timestamp; ingestion time is
        # the scope boundary, just as in the application's evidence store.
        db.execute("INSERT INTO events VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                   ("future_other_watch", PRIVATE + "_root_guid", None, "file_create", "{}", "polling",
                    1, "2020-01-01", PRIVATE, PRIVATE, 45991, "2026-10-17T01:02:06Z"))
    result = dataset.export_local_holdout(database, SELECTED)
    assert result["events"] == 5 and "file_create" not in result["kind_counts"]
    _, value = read_only_output(output)
    assert len(value["events"]) == 5


def test_collection_changes_cannot_mix_membership_and_events_from_different_snapshots(local_store, monkeypatch):
    database, output = local_store
    real_connect = sqlite3.connect
    writer = real_connect(database)
    writer.execute("PRAGMA journal_mode=WAL")
    changed = False

    class SnapshotConnection(sqlite3.Connection):
        def execute(self, sql, *args, **kwargs):
            nonlocal changed
            cursor = super().execute(sql, *args, **kwargs)
            if sql.startswith("SELECT mode FROM sessions") and not changed:
                changed = True
                writer.execute("INSERT INTO events VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                               ("concurrent_later_event", PRIVATE + "_root_guid", None, "file_create", "{}",
                                "polling", 1, "2026-10-17T01:02:06Z", PRIVATE, PRIVATE, 45991,
                                "2026-10-17T01:02:06Z"))
                writer.commit()
            return cursor

    def snapshot_connect(path, **kwargs):
        return real_connect(path, **kwargs, factory=SnapshotConnection)

    monkeypatch.setattr(dataset.sqlite3, "connect", snapshot_connect)
    try:
        result = dataset.export_local_holdout(database, SELECTED)
        assert changed and result["events"] == 5
        assert writer.execute("SELECT count(*) FROM events WHERE kind='file_create'").fetchone()[0] == 1
        _, value = read_only_output(output)
        assert all(event["kind"] != "file_create" for event in value["events"])
    finally:
        writer.close()


def test_export_orders_mixed_fractional_iso_and_equivalent_offsets_chronologically(local_store):
    database, output = local_store
    timestamps = ["2026-10-17T00:00:00.500Z", "2026-10-17T00:00:00Z",
                  "2026-10-17T05:30:00.250+05:30", "2026-10-17T00:00:00.250Z",
                  "2026-10-17T00:00:01Z"]
    with sqlite3.connect(database) as db:
        for index, stamp in enumerate(timestamps):
            db.execute("UPDATE events SET timestamp=? WHERE id=?", (stamp, PRIVATE + str(index)))
    dataset.export_local_holdout(database, SELECTED)
    text, value = read_only_output(output)
    # Equal instants use the internal event-ID tie break, matching model order.
    assert [event["kind"] for event in value["events"]] == ["network", "dns", "network", "process_start", "network"]
    assert [event["source"] for event in value["events"]] == ["polling", "sysmon", "recording", "polling", "unknown"]
    assert "timestamp" not in text and "2026-10-17" not in text and PRIVATE not in text


@pytest.mark.parametrize("column,value", [
    ("timestamp", "invalid-private-timestamp"), ("timestamp", "x" * 129),
    ("id", "x" * 129),
])
def test_invalid_or_oversized_order_fields_are_rejected_without_export(local_store, column, value):
    database, output = local_store
    with sqlite3.connect(database) as db:
        # Column names are test constants; production queries never interpolate evidence.
        db.execute(f"UPDATE events SET {column}=? WHERE id=?", (value, PRIVATE + "0"))
    with pytest.raises(dataset.DatasetError, match="ordering"):
        dataset.export_local_holdout(database, SELECTED)
    assert not output.exists()


@pytest.mark.parametrize("kwargs", [
    {"role": "training"}, {"role": "validation"}, {"label": "benign"},
    {"label": "malicious"}, {"max_events": 0}, {"max_events": True},
    {"max_events": dataset.MAX_EVENTS + 1},
])
def test_holdout_cannot_be_relabelled_or_exceed_fixed_bounds(local_store, kwargs):
    database, output = local_store
    with pytest.raises(dataset.DatasetError):
        dataset.export_local_holdout(database, SELECTED, **kwargs)
    assert not output.exists()


@pytest.mark.parametrize("session", ["", "missing_session", "session_other';DROP TABLE events;--"])
def test_session_must_be_explicit_and_existing(local_store, session):
    database, output = local_store
    with pytest.raises(dataset.DatasetError):
        dataset.export_local_holdout(database, session)
    assert not output.exists()


def test_overflow_rejects_instead_of_writing_truncated_evidence(local_store):
    database, output = local_store
    with pytest.raises(dataset.DatasetError, match="no truncated dataset"):
        dataset.export_local_holdout(database, SELECTED, max_events=4)
    assert not output.exists()


def test_process_count_and_decoded_details_are_bounded(local_store, monkeypatch):
    database, output = local_store
    monkeypatch.setattr(dataset, "MAX_PROCESSES", 1)
    with pytest.raises(dataset.DatasetError):
        dataset.export_local_holdout(database, SELECTED)
    monkeypatch.setattr(dataset, "MAX_PROCESSES", 1000)
    monkeypatch.setattr(dataset, "MAX_DETAILS_BYTES", 16)
    with pytest.raises(dataset.DatasetError):
        dataset.export_local_holdout(database, SELECTED)
    assert not output.exists()


def test_data_directory_link_cannot_redirect_output_outside_checkout(local_store, monkeypatch):
    database, output = local_store
    original_resolve = Path.resolve
    outside = database.parent / "outside"

    def redirected_resolve(path, *args, **kwargs):
        # Reproduce the result of a directory junction without requiring Windows
        # symlink privileges on the test machine.
        if path == output:
            return outside
        return original_resolve(path, *args, **kwargs)

    monkeypatch.setattr(Path, "resolve", redirected_resolve)
    with pytest.raises(dataset.DatasetError, match="inside the checkout"):
        dataset.export_local_holdout(database, SELECTED)
    assert not outside.exists() and not output.exists()


@pytest.mark.parametrize("role", ["replay", "recording"])
def test_fabricated_or_imported_scenarios_cannot_masquerade_as_local_observations(local_store, role):
    database, output = local_store
    with sqlite3.connect(database) as db:
        db.execute("UPDATE sessions SET mode=? WHERE id=?", (role, SELECTED))
    with pytest.raises(dataset.DatasetError):
        dataset.export_local_holdout(database, SELECTED)
    assert not output.exists()


@pytest.mark.parametrize("destination", ["outside", "relative", "traversal"])
def test_output_cannot_leave_ignored_local_data_tree(local_store, tmp_path, destination):
    database, output = local_store
    selected = {"outside": tmp_path / "public.json", "relative": Path("relative"),
                "traversal": output / ".." / "escape"}[destination]
    with pytest.raises(dataset.DatasetError):
        dataset.export_local_holdout(database, SELECTED, output_dir=selected)
    assert not output.exists()


def test_existing_dataset_is_not_deleted_on_filename_collision(local_store, monkeypatch):
    database, output = local_store
    output.mkdir(parents=True)
    fixed = "b" * 32
    existing = output / ("capture_" + fixed + ".json")
    existing.write_text("existing local data", encoding="utf-8")
    monkeypatch.setattr(dataset.uuid, "uuid4", lambda: SimpleNamespace(hex=fixed))
    with pytest.raises(dataset.DatasetError):
        dataset.export_local_holdout(database, SELECTED)
    assert existing.read_text(encoding="utf-8") == "existing local data"


def test_diagnostic_ids_are_random_per_capture_and_not_source_session_ids(local_store):
    database, output = local_store
    dataset.export_local_holdout(database, SELECTED)
    dataset.export_local_holdout(database, SELECTED)
    values = [json.loads(p.read_text(encoding="utf-8")) for p in output.glob("*.json")]
    assert len(values) == 2 and values[0]["capture"] != values[1]["capture"]
    assert values[0]["events"] == values[1]["events"]


def test_database_errors_do_not_echo_selected_paths_or_identifiers(local_store, capsys):
    database, output = local_store
    with sqlite3.connect(database) as db:
        db.execute("DROP TABLE events")
    assert dataset.main(["--database", str(database), "--session", SELECTED]) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert PRIVATE not in captured.err and SELECTED not in captured.err and str(database) not in captured.err
    assert "Traceback" not in captured.err and "no such table" not in captured.err
    assert not output.exists()


def test_invalid_cli_values_are_not_echoed(capsys):
    assert dataset.main(["--database", PRIVATE, "--session", SELECTED, "--max-events", PRIVATE]) == 1
    captured = capsys.readouterr()
    assert PRIVATE not in captured.err and SELECTED not in captured.err
    assert "Traceback" not in captured.err


def test_unexpected_filesystem_errors_are_not_echoed(local_store, monkeypatch, capsys):
    database, _ = local_store

    def inaccessible(*args, **kwargs):
        raise OSError(PRIVATE)

    monkeypatch.setattr(dataset, "export_local_holdout", inaccessible)
    assert dataset.main(["--database", str(database), "--session", SELECTED]) == 1
    captured = capsys.readouterr()
    assert PRIVATE not in captured.err and SELECTED not in captured.err and str(database) not in captured.err
    assert "Traceback" not in captured.err


def test_privacy_schema_rejects_new_raw_fields(local_store):
    database, output = local_store
    dataset.export_local_holdout(database, SELECTED)
    _, value = read_only_output(output)
    value["events"][0]["command_line"] = PRIVATE
    with pytest.raises(dataset.DatasetError, match="privacy schema"):
        dataset._assert_safe_payload(value)
