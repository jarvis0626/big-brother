import http.server
import os
from pathlib import Path
import queue
import subprocess
import sys
import threading
import time

import psutil
import pytest

from backend.service import Application
from backend.storage import EvidenceStore
from backend.telemetry import Collector, SysmonReader, parse_sysmon


def sysmon_xml(record=1, event_type=1, fields=None):
    fields = fields or {"ProcessGuid": "{ROOT}", "ParentProcessGuid": "{PARENT}", "ProcessId": "100",
                        "UtcTime": "2026-10-07 01:00:00.123", "Image": "C:\\Test\\root.exe", "CommandLine": "root.exe"}
    from xml.sax.saxutils import escape
    data = "".join(f'<Data Name="{escape(key)}">{escape(str(value))}</Data>' for key, value in fields.items())
    return f'<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><EventID>{event_type}</EventID><EventRecordID>{record}</EventRecordID><Computer>TEST-HOST</Computer><TimeCreated SystemTime="2026-10-07T01:00:00Z"/></System><EventData>{data}</EventData></Event>'


def test_sysmon_guid_parent_identity_and_provenance():
    value = parse_sysmon(sysmon_xml(), "epoch1")
    assert value["process_key"] == "sysmon:test-host:{root}"
    assert value["parent_key"] == "sysmon:test-host:{parent}"
    assert value["source_record_id"] == "1"
    assert value["source_epoch"] == "epoch1"
    assert value["timestamp"] == "2026-10-07T01:00:00.123+00:00"
    network = parse_sysmon(sysmon_xml(2, 3, {"ProcessGuid": "{ROOT}", "ProcessId": "100", "DestinationIp": "127.0.0.1", "DestinationPort": "5000"}))
    assert network["kind"] == "network"
    assert network["details"]["destination_ip"] == "127.0.0.1"
    assert network["details"]["destination_port"] == "5000"
    with pytest.raises(ValueError):
        parse_sysmon('<!DOCTYPE a [<!ENTITY x SYSTEM "file:///C:/secret">]><Event/>')


def test_sysmon_disconnect_reconnect_and_clear_preserve_gaps(tmp_path):
    store = EvidenceStore(tmp_path / "test.db")
    reader = SysmonReader(store)
    reader.api = object()
    reader.cursor = 10
    results = [[sysmon_xml(10)], [sysmon_xml(11)]]
    reader.query = lambda *args, **kwargs: results.pop(0)
    try:
        assert reader.poll()[0]["source_record_id"] == "11"
        assert reader.available and reader.cursor == 11

        def unavailable(*args, **kwargs):
            raise OSError("Disconnected")

        reader.query = unavailable
        assert reader.poll() == [] and not reader.available
        assert any("disconnected" in gap["detail"] for gap in store.gaps())
        old_epoch = reader.epoch
        results = [[sysmon_xml(2)], [sysmon_xml(3)]]
        reader.query = lambda *args, **kwargs: results.pop(0)
        reader.poll()
        assert reader.available
        assert reader.epoch != old_epoch
        assert any("cleared" in gap["detail"] for gap in store.gaps())
        assert store.get_meta("sysmon_cursor") == 3
    finally:
        store.close()


def test_queue_backpressure_is_bounded_and_reported(tmp_path):
    store = EvidenceStore(tmp_path / "test.db")
    store.settings({"max_queue": 128})
    collector = Collector.__new__(Collector)
    collector.store = store
    collector.queue = queue.Queue(maxsize=16384)
    collector.dropped = 0
    try:
        for number in range(200):
            collector.submit({"n": number})
        assert collector.queue.qsize() == 128
        assert collector.dropped == 72
        assert any("queue" in gap["detail"] for gap in store.gaps())
    finally:
        store.close()


def test_stop_drains_already_queued_evidence_before_session_cutoff(tmp_path):
    resources = Path(__file__).resolve().parents[1] / "resources"
    app = Application(resources, tmp_path / "data")
    try:
        session = app.store.create_session("queued fixture", "live", "fixture:root")
        with app.collector.lock:
            for number in range(200):
                app.collector.submit({"process_key": "fixture:root", "kind": "file_create", "pid": 900000,
                                      "source": "fixture", "source_record_id": str(number),
                                      "details": {"target": "C:\\Fabricated\\never-created.txt"}})
            state = app.stop(session["id"])
        assert state["session"]["status"] == "stopped"
        assert len(state["events"]) == 200
        assert app.collector.queue.unfinished_tasks == 0
    finally:
        app.close()


@pytest.mark.skipif(os.name != "nt", reason="Real Windows process/network validation")
def test_windows_harmless_workload_tracks_surviving_child_and_loopback(tmp_path):
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            time.sleep(1.4)  # Keep a connection visible to snapshot telemetry.
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"local validation")

        def log_message(self, *args):
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    child_script = tmp_path / "benign_child.py"
    child_script.write_text("""import http.client, pathlib, sys, time
directory = pathlib.Path(sys.argv[1])
port = int(sys.argv[2])
(directory / 'benign-created.txt').write_text('Harmless local telemetry validation')
for delay in (0.0, 2.2):
    time.sleep(delay)
    connection = http.client.HTTPConnection('127.0.0.1', port, timeout=5)
    connection.request('GET', '/')
    connection.getresponse().read()
    connection.close()
time.sleep(1)
""", encoding="utf-8")
    parent_script = tmp_path / "benign_parent.py"
    parent_script.write_text("""import pathlib, subprocess, sys, time
time.sleep(0.8)
child = subprocess.Popen([sys.executable, sys.argv[1], sys.argv[2], sys.argv[3]], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
pathlib.Path(sys.argv[2], 'child.pid').write_text(str(child.pid))
time.sleep(1.8)
""", encoding="utf-8")
    resources = Path(__file__).resolve().parents[1] / "resources"
    app = Application(resources, tmp_path / "data")
    app.store.settings({"poll_interval": 0.5})
    parent = subprocess.Popen([sys._base_executable, str(parent_script), str(child_script), str(tmp_path), str(server.server_port)],
                              stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                              creationflags=subprocess.CREATE_NO_WINDOW)
    child_pid = None
    try:
        session = app.watch(parent.pid)
        deadline = time.monotonic() + 14
        state = app.state(session["id"])
        while time.monotonic() < deadline:
            if (tmp_path / "child.pid").exists():
                child_pid = int((tmp_path / "child.pid").read_text())
            state = app.state(session["id"])
            parent_end = [event for event in state["events"] if event["kind"] == "process_end" and event["pid"] == parent.pid]
            late_network = [event for event in state["events"] if event["kind"] == "network" and event["pid"] == child_pid
                            and parent_end and event["timestamp"] > parent_end[0]["timestamp"]]
            child_end = [event for event in state["events"] if event["kind"] == "process_end" and event["pid"] == child_pid]
            if late_network and child_end:
                break
            time.sleep(0.2)
        assert (tmp_path / "benign-created.txt").is_file()
        children = [node for node in state["processes"] if node["pid"] == child_pid]
        assert len(children) == 1, (state["collector"], state["processes"], state["events"])
        assert children[0]["parent_key"] == session["root_key"]
        assert parent_end, state["events"]
        assert late_network, state["events"]
        assert all(event["details"]["destination_ip"] == "127.0.0.1" for event in late_network)
        app.analyze(force=True, session_id=session["id"])
        assert any("continued connecting" in finding["title"] for finding in app.store.incidents(session["id"]))
        assert session["ancestry_complete"] is False
        assert any(item["status"] == "unavailable" for item in state["coverage"])  # Honest file/traffic blind spots.
    finally:
        app.close()
        if parent.poll() is None:
            parent.terminate()
        parent.wait(timeout=5)
        if child_pid:
            try:
                child = psutil.Process(child_pid)
                if str(child_script) in child.cmdline():
                    child.terminate()
                    child.wait(timeout=5)
            except psutil.Error:
                pass
        server.shutdown()
        server.server_close()
        server_thread.join(timeout=3)
