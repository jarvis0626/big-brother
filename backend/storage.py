"""Bounded local SQLite evidence store. Telemetry strings are data, never SQL."""
from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
import uuid
from datetime import datetime, timezone, timedelta
from pathlib import Path
from contextlib import nullcontext


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def timestamp(value) -> str:
    if isinstance(value, (float, int)):
        return datetime.fromtimestamp(value, timezone.utc).isoformat(timespec="milliseconds")
    if not value:
        return now()
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        normalized = parsed.astimezone(timezone.utc) if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
        return normalized.isoformat(timespec="milliseconds")
    except ValueError:
        raise ValueError("Invalid event timestamp")


def poll_key(pid: int, created: float) -> str:
    return f"poll:{int(pid)}:{created:.6f}"


def event_id(event: dict) -> str:
    source = event.get("source", "unknown")
    record = event.get("source_record_id")
    if record is not None:
        material = f"{source}:{event.get('source_epoch', '')}:{record}"
    else:
        material = json.dumps(event, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return "evt_" + hashlib.sha256(material.encode("utf-8")).hexdigest()[:24]


class EvidenceStore:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.lock = threading.RLock()
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.executescript("""
        PRAGMA journal_mode=WAL;
        PRAGMA foreign_keys=ON;
        PRAGMA secure_delete=ON;
        CREATE TABLE IF NOT EXISTS sessions(id TEXT PRIMARY KEY, name TEXT, mode TEXT, status TEXT,
          started_at TEXT, ended_at TEXT, root_key TEXT, ancestry_complete INTEGER);
        CREATE TABLE IF NOT EXISTS processes(key TEXT PRIMARY KEY, pid INTEGER, parent_key TEXT,
          name TEXT, image TEXT, command_line TEXT, started_at TEXT, ended_at TEXT, uncertain INTEGER);
        CREATE TABLE IF NOT EXISTS events(id TEXT PRIMARY KEY, process_key TEXT, parent_key TEXT,
          pid INTEGER, timestamp TEXT, ingested_at TEXT, kind TEXT, image TEXT, command_line TEXT,
          details TEXT, source TEXT, source_record_id TEXT, uncertain INTEGER);
        CREATE INDEX IF NOT EXISTS event_process ON events(process_key,timestamp);
        CREATE INDEX IF NOT EXISTS process_parent ON processes(parent_key);
        CREATE TABLE IF NOT EXISTS membership(session_id TEXT REFERENCES sessions(id) ON DELETE CASCADE,
          process_key TEXT, PRIMARY KEY(session_id,process_key));
        CREATE TABLE IF NOT EXISTS aliases(alias TEXT PRIMARY KEY, process_key TEXT);
        CREATE TABLE IF NOT EXISTS incidents(id TEXT PRIMARY KEY, session_id TEXT REFERENCES sessions(id)
          ON DELETE CASCADE, body TEXT);
        CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT);
        CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY,value TEXT);
        CREATE TABLE IF NOT EXISTS gaps(id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT, detail TEXT);
        """)
        # A previous process cannot still collect after the private service exits.
        old = self.db.execute("SELECT count(*) FROM sessions WHERE status IN ('watching','paused')").fetchone()[0]
        if old:
            self.db.execute("UPDATE sessions SET status='interrupted',ended_at=? WHERE status IN ('watching','paused')", (now(),))
            self.gap("Service restarted; prior collection sessions were interrupted.")
        self.db.commit()

    def close(self):
        with self.lock:
            self.db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            self.db.close()

    def get_meta(self, key, default=None):
        with self.lock:
            row = self.db.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
            return json.loads(row[0]) if row else default

    def set_meta(self, key, value):
        with self.lock, self.db:
            self.db.execute("INSERT OR REPLACE INTO meta VALUES(?,?)", (key, json.dumps(value)))

    def get_settings(self):
        values = {"retention_days": 7, "max_events": 20000, "poll_interval": 1.0,
                  "max_queue": 4096, "max_sessions": 20, "close_to_tray": True, "llm_provider": "disabled"}
        with self.lock:
            values.update({r[0]: json.loads(r[1]) for r in self.db.execute("SELECT key,value FROM settings")})
        return values

    def settings(self, values):
        allowed = {"retention_days": (1, 90), "max_events": (500, 100000),
                   "poll_interval": (0.5, 10), "max_queue": (128, 16384), "max_sessions": (1, 100)}
        for key, value in values.items():
            if key in allowed:
                low, high = allowed[key]
                if isinstance(value, bool) or not isinstance(value, (int, float)) or not low <= value <= high:
                    raise ValueError(f"{key} must be between {low} and {high}")
                if key != "poll_interval" and not isinstance(value, int):
                    raise ValueError(f"{key} must be an integer")
            elif key == "close_to_tray":
                if not isinstance(value, bool):
                    raise ValueError("close_to_tray must be a boolean")
            elif key == "llm_provider":
                if value != "disabled":
                    raise ValueError("External LLM requests are disabled in this version")
            else:
                raise ValueError(f"Unsupported setting: {key}")
        with self.lock, self.db:
            for key, value in values.items():
                self.db.execute("INSERT OR REPLACE INTO settings VALUES(?,?)", (key, json.dumps(value)))
        self.prune()
        return self.get_settings()

    def gap(self, detail):
        with self.lock, self.db:
            self.db.execute("INSERT INTO gaps(timestamp,detail) VALUES(?,?)", (now(), str(detail)[:2000]))
            self.db.execute("DELETE FROM gaps WHERE id NOT IN(SELECT id FROM gaps ORDER BY id DESC LIMIT 100)")

    def gaps(self):
        with self.lock:
            return [dict(r) for r in self.db.execute("SELECT timestamp,detail FROM gaps ORDER BY id DESC LIMIT 30")]

    def resolve(self, key):
        with self.lock:
            row = self.db.execute("SELECT process_key FROM aliases WHERE alias=?", (key,)).fetchone()
            return row[0] if row else key

    def alias(self, alias, canonical):
        canonical = self.resolve(canonical)
        if alias == canonical:
            return
        with self.lock, self.db:
            self.db.execute("INSERT OR REPLACE INTO aliases VALUES(?,?)", (alias, canonical))
            # Late GUID association merges evidence, preserving the original stable session root.
            self.db.execute("UPDATE events SET process_key=? WHERE process_key=?", (canonical, alias))
            self.db.execute("UPDATE events SET parent_key=? WHERE parent_key=?", (canonical, alias))
            self.db.execute("UPDATE processes SET parent_key=? WHERE parent_key=?", (canonical, alias))
            self.db.execute("INSERT OR IGNORE INTO membership SELECT session_id,? FROM membership WHERE process_key=?", (canonical, alias))
            self.db.execute("DELETE FROM membership WHERE process_key=?", (alias,))
            self.db.execute("DELETE FROM processes WHERE key=?", (alias,))
            self.reconcile()

    def create_session(self, name, mode, root_key, ancestry_complete=False, started_at=None, *, defer=False):
        sid = "session_" + uuid.uuid4().hex
        with self.lock, (nullcontext() if defer else self.db):
            self.db.execute("INSERT INTO sessions VALUES(?,?,?,?,?,?,?,?)", (
                sid, str(name)[:200], mode, "replay" if mode == "replay" else "watching",
                started_at or now(), None, root_key, int(ancestry_complete)))
            self.db.execute("INSERT OR IGNORE INTO membership VALUES(?,?)", (sid, root_key))
            self.reconcile()
        return self.session(sid)

    def session(self, sid):
        with self.lock:
            row = self.db.execute("SELECT * FROM sessions WHERE id=?", (sid,)).fetchone()
            if row is None:
                raise ValueError("Session does not exist")
            value = dict(row)
            value["ancestry_complete"] = bool(value["ancestry_complete"])
            return value

    def sessions(self):
        with self.lock:
            values = [dict(r) for r in self.db.execute("""SELECT * FROM sessions WHERE status IN ('watching','paused')
                OR id IN(SELECT id FROM sessions ORDER BY started_at DESC LIMIT 100) ORDER BY started_at DESC""")]
            for value in values:
                value["ancestry_complete"] = bool(value["ancestry_complete"])
            return values

    def set_status(self, sid, status):
        self.session(sid)
        with self.lock, self.db:
            self.db.execute("UPDATE sessions SET status=?,ended_at=? WHERE id=?", (
                status, now() if status == "stopped" else None, sid))

    def ingest(self, event, *, defer=False):
        event = dict(event)
        if not event.get("process_key") or not event.get("kind"):
            raise ValueError("Event requires process_key and kind")
        event["timestamp"] = timestamp(event.get("timestamp"))
        event["id"] = event.get("id") or event_id(event)
        key = self.resolve(event["process_key"])
        parent = self.resolve(event.get("parent_key")) if event.get("parent_key") else None
        event["details"] = event.get("details", {})
        details = json.dumps(event["details"], ensure_ascii=False)
        if len(details) > 32768:
            event["details"] = {"truncated": True, "summary": details[:16000]}
            details = json.dumps(event["details"])
        image = str(event.get("image") or "")[:4096]
        command = str(event.get("command_line") or "")[:8192]
        with self.lock, (nullcontext() if defer else self.db):
            inserted = self.db.execute("INSERT OR IGNORE INTO events VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)", (
                event["id"], key, parent, event.get("pid", 0), event["timestamp"], now(), event["kind"],
                image, command, details, event.get("source", "unknown"),
                str(event["source_record_id"]) if event.get("source_record_id") is not None else None,
                int(event.get("uncertain", False)))).rowcount
            if not inserted:
                return False
            name = image.replace("\\", "/").split("/")[-1] or str(event.get("name", "Unknown process"))[:200]
            self.db.execute("INSERT OR IGNORE INTO processes VALUES(?,?,?,?,?,?,?,?,?)", (
                key, event.get("pid", 0), parent, name, image, command, event["timestamp"], None,
                int(event.get("uncertain", False))))
            if event["kind"] == "process_start":
                self.db.execute("UPDATE processes SET parent_key=COALESCE(?,parent_key),name=?,image=?,command_line=?,started_at=?,uncertain=? WHERE key=?", (
                    parent, name, image, command, event["timestamp"], int(event.get("uncertain", False)), key))
                self.db.execute("UPDATE events SET parent_key=? WHERE process_key=? AND parent_key IS NULL", (parent, key))
            elif event["kind"] == "process_end":
                self.db.execute("UPDATE processes SET ended_at=? WHERE key=?", (event["timestamp"], key))
            if not defer:
                self.reconcile()
        return True

    def reconcile(self):
        # Iteration is bounded by the number of stored nodes; cycles never expand membership forever.
        while self.db.execute("""INSERT OR IGNORE INTO membership(session_id,process_key)
            SELECT m.session_id,p.key FROM membership m JOIN processes p ON p.parent_key=m.process_key
            JOIN sessions s ON s.id=m.session_id WHERE s.status IN ('watching','paused','replay')""").rowcount:
            pass

    def process(self, key):
        with self.lock:
            row = self.db.execute("SELECT * FROM processes WHERE key=?", (self.resolve(key),)).fetchone()
            return dict(row) if row else None

    def processes(self, sid):
        with self.lock:
            return [{**dict(r), "uncertain": bool(r["uncertain"])} for r in self.db.execute(
                "SELECT p.* FROM processes p JOIN membership m ON p.key=m.process_key WHERE m.session_id=? ORDER BY p.started_at LIMIT 1000", (sid,))]

    def events(self, sid, limit=2000):
        with self.lock:
            rows = self.db.execute("""SELECT * FROM (SELECT e.* FROM events e JOIN membership m
                ON e.process_key=m.process_key JOIN sessions s ON s.id=m.session_id WHERE m.session_id=?
                AND (s.ended_at IS NULL OR e.ingested_at <= s.ended_at)
                ORDER BY e.timestamp DESC,e.id DESC LIMIT ?) ORDER BY timestamp,id""", (sid, min(limit, 100000))).fetchall()
            return [{**dict(r), "session_id": sid, "details": json.loads(r["details"]), "uncertain": bool(r["uncertain"])} for r in rows]

    def save_incidents(self, sid, incidents):
        with self.lock, self.db:
            self.db.execute("DELETE FROM incidents WHERE session_id=?", (sid,))
            self.db.executemany("INSERT INTO incidents VALUES(?,?,?)", ((i["id"], sid, json.dumps(i, ensure_ascii=False)) for i in incidents))

    def incidents(self, sid):
        with self.lock:
            return [json.loads(r[0]) for r in self.db.execute("SELECT body FROM incidents WHERE session_id=?", (sid,))]

    def delete_session(self, sid):
        self.session(sid)
        with self.lock, self.db:
            self.db.execute("DELETE FROM sessions WHERE id=?", (sid,))
            self.db.execute("DELETE FROM meta WHERE key=?", ("recording:" + sid,))
            self.db.execute("DELETE FROM events WHERE process_key NOT IN(SELECT process_key FROM membership)")
            self.db.execute("DELETE FROM processes WHERE key NOT IN(SELECT process_key FROM membership)")
            self.db.execute("DELETE FROM aliases WHERE process_key NOT IN(SELECT key FROM processes)")
        with self.lock:
            self.db.execute("PRAGMA wal_checkpoint(PASSIVE)")

    def prune(self):
        options = self.get_settings()
        cutoff = (datetime.now(timezone.utc) - timedelta(days=options["retention_days"])).isoformat()
        with self.lock, self.db:
            # Replay timestamps are historical scenario time; retention uses ingestion time.
            old = self.db.execute("SELECT count(*) FROM events WHERE ingested_at<?", (cutoff,)).fetchone()[0]
            count = self.db.execute("SELECT count(*) FROM events").fetchone()[0]
            dropped = old + max(0, count - old - options["max_events"])
            self.db.execute("DELETE FROM events WHERE ingested_at<?", (cutoff,))
            self.db.execute("DELETE FROM events WHERE id NOT IN(SELECT id FROM events ORDER BY ingested_at DESC,id DESC LIMIT ?)", (options["max_events"],))
            if dropped:
                self.db.execute("DELETE FROM incidents")
                self.gap(f"Retention removed {dropped} evidence events; earlier activity may be incomplete.")
            self.db.execute("DELETE FROM sessions WHERE started_at<? AND status NOT IN ('watching','paused')", (cutoff,))
            self.db.execute("DELETE FROM meta WHERE key LIKE 'recording:%' AND substr(key,11) NOT IN(SELECT id FROM sessions)")
            self.db.execute("DELETE FROM processes WHERE key NOT IN(SELECT process_key FROM membership) AND key NOT IN(SELECT process_key FROM events)")
        return dropped
