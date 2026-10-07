"""Private newline-delimited IPC service. There is no listening socket or shell API."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from contextlib import nullcontext

import psutil

from backend.explain import ExplanationEngine
from backend.storage import EvidenceStore, now, poll_key
from backend.telemetry import Collector, list_processes, process_info
from backend.imports import load_recording, KINDS

try:
    from backend.model import BehavioralModel
except ImportError:
    BehavioralModel = None

METHODS = {
    "state": {"session_id"}, "list_processes": set(), "watch": {"pid"}, "launch": {"path"},
    "replay": {"scenario"}, "pause": {"session_id", "paused"}, "stop": {"session_id"},
    "settings": {"retention_days", "max_events", "poll_interval", "max_queue", "max_sessions", "close_to_tray", "llm_provider"},
    "delete_session": {"session_id"}, "export": {"session_id"}, "shutdown": set(),
    "import_recording": {"path"},
}


class UnavailableModel:
    def __init__(self, reason):
        self.metadata = {"name": "Trained behavioral model", "version": "unavailable", "status": "unavailable",
                         "threshold": None, "limitations": [reason, "Transparent reference rules remain separately labeled; no model score is substituted."]}

    def score(self, events):
        return None


class Application:
    def __init__(self, resources: Path, data_dir: Path, start_collector=True):
        self.resources = Path(resources)
        self.store = EvidenceStore(Path(data_dir) / "big-brother.sqlite3")
        self.lock = threading.RLock()
        self.shutdown_requested = False
        self.current_session = None
        self.last_analysis = 0
        self.last_model_error = None
        self.explanations = ExplanationEngine(self.resources)
        try:
            self.model = BehavioralModel(self.resources / "models") if BehavioralModel else UnavailableModel("Model inference module is missing.")
        except Exception as error:
            self.model = UnavailableModel(f"Model could not load: {type(error).__name__}: {error}")
        self.collector = Collector(self.store, self.analyze) if start_collector else None
        self.store.prune()

    def model_metadata(self):
        value = self.model.metadata
        return value() if callable(value) else value

    def coverage(self, session=None):
        if session and session["mode"] == "recording":
            metadata = self.store.get_meta("recording:" + session["id"], {})
            observed_kinds = set(metadata.get("observed_kinds", []))
            return [{"kind": kind, "status": "recorded" if kind in observed_kinds else "unavailable",
                     "backend": "recording", "detail": "Imported capture contains this event type; capture completeness is unknown."
                     if kind in observed_kinds else "This capture contains no events of this type; absence does not establish safety."}
                    for kind in sorted(KINDS)]
        if self.collector:
            return self.collector.coverage()
        return [{"kind": "replay", "status": "fabricated", "backend": "replay", "detail": "Fabricated recorded events; no activity is executed."}]

    def analyze(self, force=False, session_id=None):
        with self.lock:
            if not force and time.monotonic() - self.last_analysis < 1:
                return
            self.last_analysis = time.monotonic()
            for session in self.store.sessions():
                if session_id and session["id"] != session_id:
                    continue
                if session["status"] == "paused":
                    continue
                if not force and session["status"] not in ("watching", "replay", "recording"):
                    continue
                events = self.store.events(session["id"], limit=2000)
                score = None
                if events and self.model_metadata().get("status") not in ("unavailable", "error"):
                    try:
                        score = self.model.score(events)
                        self.last_model_error = None
                    except Exception as error:
                        reason = f"Model inference failed: {type(error).__name__}: {error}"
                        if reason != self.last_model_error:
                            self.store.gap(reason)
                        self.last_model_error = reason
                findings = self.explanations.incidents(session, events, score, self.coverage(session))
                self.store.save_incidents(session["id"], findings)

    def state(self, session_id=None):
        with self.lock:
            sessions = self.store.sessions()
            sid = session_id or self.current_session or (sessions[0]["id"] if sessions else None)
            session = self.store.session(sid) if sid else None
            if session and session["status"] != "paused":
                self.analyze(session_id=sid)
            metadata = dict(self.model_metadata())
            if self.last_model_error:
                metadata["status"] = "error"
                metadata["limitations"] = list(metadata.get("limitations", [])) + [self.last_model_error]
            return {"sessions": sessions, "session": session,
                    "events": self.store.events(sid) if sid else [],
                    "processes": self.store.processes(sid) if sid else [],
                    "incidents": self.store.incidents(sid) if sid else [],
                    "collector": self.collector.state() if self.collector else {"status": "idle", "backend": "replay", "gaps": self.store.gaps(), "dropped_events": 0},
                    "model": metadata, "settings": self.store.get_settings(), "coverage": self.coverage(session),
                    "recording": self.store.get_meta("recording:" + sid) if sid else None}

    def check_session_limit(self):
        count = len([session for session in self.store.sessions() if session["status"] in ("watching", "paused")])
        if count >= self.store.get_settings()["max_sessions"]:
            raise ValueError("Active session limit reached. Stop an existing session first.")

    def watch(self, pid):
        if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 0:
            raise ValueError("A positive integer process ID is required")
        self.check_session_limit()
        try:
            info = process_info(psutil.Process(pid))
        except psutil.Error as error:
            raise ValueError("Selected process no longer exists or is inaccessible") from error
        if not info:
            raise ValueError("Selected process no longer exists or is inaccessible")
        session = self.store.create_session(info["name"], "live", info["key"], False)
        self.current_session = session["id"]
        if self.collector:
            self.collector.watch_seed(info, live_existing=True)
        return session

    def launch(self, path):
        self.check_session_limit()
        if not isinstance(path, str) or len(path) > 4096:
            raise ValueError("Executable path must be a string")
        executable = Path(path)
        if not executable.is_absolute() or not executable.is_file() or executable.suffix.lower() != ".exe":
            raise ValueError("Choose an existing absolute .exe path")
        # This is the only code path that executes user-selected programs.
        process = subprocess.Popen([str(executable)], shell=False, stdin=subprocess.DEVNULL,
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                   cwd=str(executable.parent), creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)
        try:
            info = process_info(psutil.Process(process.pid))
        except psutil.Error:
            info = None
        if info:
            session = self.store.create_session(executable.name, "live", info["key"], True)
            if self.collector:
                self.collector.watch_seed(info, live_existing=False)
        else:
            key = f"launch:{process.pid}:{uuid.uuid4().hex}"
            session = self.store.create_session(executable.name, "live", key, False)
            self.store.ingest({"process_key": key, "pid": process.pid, "kind": "process_start", "timestamp": now(),
                               "image": str(executable), "command_line": str(executable), "source": "launcher", "uncertain": True,
                               "details": {"launch_returned_pid": True, "process_exited_before_snapshot": True}})
            self.store.gap("Launched executable exited before its identity snapshot; descendant attribution may be incomplete.")
        self.current_session = session["id"]
        return session

    def replay(self, scenario="investigation"):
        if scenario not in ("investigation", "ordinary"):
            raise ValueError("Unknown replay scenario")
        fixture = json.loads((self.resources / "replays" / f"{scenario}.json").read_text(encoding="utf-8"))
        if fixture.get("fabricated") is not True:
            raise ValueError("Replay fixture must explicitly identify its provenance")
        nonce = uuid.uuid4().hex
        key_map = {event["process_key"]: f"{event['process_key']}:{nonce}" for event in fixture["events"]}
        session = self.store.create_session(fixture["name"], "replay", key_map[fixture["root_key"]], True)
        self.current_session = session["id"]
        for event in fixture["events"]:
            event = {**event, "process_key": key_map[event["process_key"]], "source": f"replay:{scenario}",
                     "source_epoch": nonce, "uncertain": False, "details": {**event.get("details", {}), "fabricated": True}}
            if event.get("parent_key"):
                event["parent_key"] = key_map[event["parent_key"]]
            self.store.ingest(event)
        self.store.prune()
        self.analyze(force=True, session_id=session["id"])
        return session

    def import_recording(self, path):
        recording = load_recording(path)
        nonce = uuid.uuid4().hex
        keys = {event["process_key"] for event in recording["events"]}
        keys.update(event["parent_key"] for event in recording["events"] if event["parent_key"])
        mapping = {key: "import:" + nonce + ":" + key for key in keys}
        session = self.store.create_session(recording["name"], "recording", mapping[recording["events"][0]["process_key"]], False)
        try:
            with self.store.lock, self.store.db:
                self.store.db.executemany("INSERT OR IGNORE INTO membership VALUES(?,?)",
                                         ((session["id"], mapping[key]) for key in {e["process_key"] for e in recording["events"]}))
                for event in recording["events"]:
                    event = {**event, "process_key": mapping[event["process_key"]],
                             "parent_key": mapping.get(event["parent_key"]),
                             "source": "recording:" + nonce, "source_epoch": nonce}
                    event["id"] = "evt_" + hashlib.sha256(json.dumps(event, sort_keys=True).encode()).hexdigest()[:24]
                    self.store.ingest(event, defer=True)
                self.store.db.execute("UPDATE sessions SET status='recording' WHERE id=?", (session["id"],))
            self.store.set_meta("recording:" + session["id"],
                                {"provenance": recording["provenance"], "coverage": recording["coverage"],
                                 "imported_events": recording["event_count"],
                                 "observed_kinds": sorted({event["kind"] for event in recording["events"]})})
        except Exception:
            self.store.delete_session(session["id"])
            raise
        self.current_session = session["id"]
        self.store.prune()
        self.analyze(force=True, session_id=session["id"])
        return self.store.session(session["id"])

    def pause(self, session_id, paused):
        if not isinstance(paused, bool):
            raise ValueError("paused must be a boolean")
        session = self.store.session(session_id)
        if session["status"] in ("stopped", "interrupted"):
            raise ValueError("This session has stopped; start a new watch")
        status = "paused" if paused else session["mode"] if session["mode"] in ("replay", "recording") else "watching"
        self.store.set_status(session_id, status)
        if not paused:
            self.analyze(force=True, session_id=session_id)
        return self.state(session_id)

    def stop(self, session_id=None):
        # Freeze producers and drain committed evidence before recording the cutoff.
        with self.collector.lock if self.collector else nullcontext():
            if self.collector:
                self.collector.flush()
            sessions = [self.store.session(session_id)] if session_id else self.store.sessions()
            for session in sessions:
                if session["status"] in ("watching", "paused", "replay", "recording"):
                    self.analyze(force=True, session_id=session["id"])
                    self.store.set_status(session["id"], "stopped")
            if self.collector and not self.collector.active_keys():
                self.collector.status = "idle"
                self.collector.pending.clear()
        return self.state(session_id)

    def export(self, session_id):
        state = self.state(session_id)
        return {"application": "Big Brother", "report_schema": 1, "exported_at": now(),
                "session": state["session"], "processes": state["processes"], "events": self.store.events(session_id, limit=100000),
                "incidents": state["incidents"], "model": state["model"], "coverage": state["coverage"],
                "collector": state["collector"],
                "recording": state["recording"],
                "notice": "Contains sensitive local telemetry. Replay is fabricated. Scores are not probabilities. No findings do not establish safety."}

    def delete_session(self, session_id):
        self.stop(session_id)
        self.store.delete_session(session_id)
        if self.current_session == session_id:
            self.current_session = None
        return self.state()

    def dispatch(self, method, params):
        if method not in METHODS:
            raise ValueError("Unsupported IPC method")
        if not isinstance(params, dict) or any(key not in METHODS[method] for key in params):
            raise ValueError("Unsupported IPC parameters")
        if method == "shutdown":
            self.shutdown_requested = True
            return {"shutdown": True}
        if method == "list_processes":
            return list_processes()
        if method == "settings":
            return self.store.settings(params)
        target = getattr(self, method)
        try:
            return target(**params)
        except TypeError as error:
            raise ValueError("Missing or invalid IPC parameters") from error

    def close(self):
        if self.collector:
            self.collector.close()
        for session in self.store.sessions():
            if session["status"] in ("watching", "paused"):
                self.store.set_status(session["id"], "stopped")
        self.store.close()


def self_test(resources):
    with tempfile.TemporaryDirectory(prefix="big-brother-self-test-") as directory:
        app = Application(resources, Path(directory), start_collector=False)
        try:
            session = app.replay()
            state = app.state(session["id"])
            assert len(state["processes"]) == 4, "Process chain reconstruction failed"
            assert len(state["events"]) == 13, "Duplicate suppression failed"
            assert len(state["incidents"]) >= 2, "Evidence rules failed"
            ids = {event["id"] for event in state["events"]}
            assert all(set(fact["event_ids"]).issubset(ids) and fact["event_ids"]
                       for finding in state["incidents"] for fact in finding["explanation"]["observed"])
            assert state["model"]["status"] not in ("unavailable", "error"), "Trained model unavailable"
            result = app.model.score(state["events"])
            assert result is not None and "score" in result, "Trained inference returned no score"
            return {"passed": True, "events": len(state["events"]), "processes": len(state["processes"]),
                    "incidents": len(state["incidents"]), "model": state["model"], "model_score": result["score"],
                    "telemetry": "Fabricated replay; real model inference. Live Windows coverage tested separately."}
        finally:
            app.close()


def serve(app, source, sink):
    max_bytes = 65536
    while not app.shutdown_requested:
        line = source.readline(max_bytes + 1)
        if not line:
            break
        request_id = None
        try:
            if len(line) > max_bytes:
                while line and not line.endswith(b"\n" if isinstance(line, bytes) else "\n"):
                    line = source.readline(max_bytes + 1)
                raise ValueError("IPC request exceeds its size limit")
            request = json.loads(line)
            if not isinstance(request, dict) or set(request) - {"id", "method", "params"}:
                raise ValueError("Invalid IPC request envelope")
            request_id = request.get("id")
            if isinstance(request_id, bool) or not isinstance(request_id, (str, int)) or len(str(request_id)) > 128:
                request_id = None
                raise ValueError("Invalid IPC request identifier")
            method = request.get("method")
            if not isinstance(method, str):
                raise ValueError("IPC method must be a string")
            result = app.dispatch(method, request.get("params", {}))
            response = {"id": request_id, "result": result}
        except Exception as error:
            response = {"id": request_id, "error": {"code": "REQUEST_FAILED", "message": str(error)[:1000]}}
        sink.write(json.dumps(response, ensure_ascii=False, allow_nan=False) + "\n")
        sink.flush()


def main():
    parser = argparse.ArgumentParser(description="Big Brother private local evidence service")
    parser.add_argument("--resources", type=Path, default=Path(__file__).resolve().parent.parent / "resources")
    parser.add_argument("--data-dir", type=Path, default=Path(os.environ.get("LOCALAPPDATA", str(Path.home()))) / "Big Brother")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if args.self_test:
        try:
            print(json.dumps(self_test(args.resources), ensure_ascii=False))
            return 0
        except Exception as error:
            print(json.dumps({"passed": False, "error": str(error)}))
            return 1
    app = Application(args.resources, args.data_dir)
    try:
        serve(app, sys.stdin.buffer, sys.stdout)
    finally:
        app.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
