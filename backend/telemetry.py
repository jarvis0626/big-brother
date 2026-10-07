"""Read-only Windows Event Log telemetry and explicitly reduced process polling."""
from __future__ import annotations

import ctypes
import json
import os
import queue
import threading
import time
import uuid
from collections import deque
from datetime import datetime, timezone
import xml.etree.ElementTree as ET

import psutil

from backend.storage import now, poll_key, timestamp

SYSMON_CHANNEL = "Microsoft-Windows-Sysmon/Operational"
EVENT_KINDS = {1: "process_start", 3: "network", 5: "process_end", 7: "image_load", 8: "remote_thread", 9: "raw_access",
               10: "process_access", 11: "file_create", 12: "registry", 13: "registry",
               14: "registry", 22: "dns", 23: "file_delete", 26: "file_delete"}
NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}


def parse_sysmon(xml: str, epoch: str = ""):
    if len(xml) > 262144 or "<!DOCTYPE" in xml.upper() or "<!ENTITY" in xml.upper():
        raise ValueError("Unsafe or oversized event XML")
    root = ET.fromstring(xml)
    system = root.find("e:System", NS)
    event_type = int(system.findtext("e:EventID", "0", NS))
    data = {v.attrib.get("Name", ""): (v.text or "")[:8192] for v in root.findall("e:EventData/e:Data", NS)}
    record = system.findtext("e:EventRecordID", "0", NS)
    if event_type not in EVENT_KINDS:
        return None
    guid = data.get("ProcessGuid") or data.get("SourceProcessGUID") or data.get("SourceProcessGuid")
    if not guid:
        return None
    computer = system.findtext("e:Computer", "local", NS).lower()
    key = f"sysmon:{computer}:{guid.lower()}"
    parent = data.get("ParentProcessGuid")
    details = dict(data)
    details["sysmon_event_id"] = event_type
    for old, new in [("DestinationIp", "destination_ip"), ("DestinationPort", "destination_port"),
                     ("TargetFilename", "target"), ("TargetObject", "target"), ("QueryName", "query")]:
        if old in data:
            details[new] = data[old]
    return {"process_key": key, "parent_key": f"sysmon:{computer}:{parent.lower()}" if parent else None,
            "pid": int(data.get("ProcessId") or data.get("SourceProcessId") or 0),
            "timestamp": timestamp(data.get("UtcTime") or system.find("e:TimeCreated", NS).attrib["SystemTime"]),
            "kind": EVENT_KINDS[event_type], "image": data.get("Image") or data.get("SourceImage", ""),
            "command_line": data.get("CommandLine", ""), "details": details, "source": "sysmon",
            "source_record_id": record, "source_epoch": epoch, "uncertain": False}


class SysmonReader:
    """Uses documented EvtQuery/EvtNext/EvtRender; no service/driver installation."""
    def __init__(self, store):
        self.store = store
        self.available = False
        self.detail = "Windows Sysmon channel unavailable on this platform"
        self.cursor = store.get_meta("sysmon_cursor", 0)
        self.epoch = store.get_meta("sysmon_epoch", "") or uuid.uuid4().hex
        self.initialized = False
        if os.name != "nt":
            self.api = None
            return
        self.api = ctypes.WinDLL("wevtapi", use_last_error=True)
        self.detail = "Sysmon channel not checked yet; start a watch to check existing telemetry."
        self.api.EvtQuery.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_uint32]
        self.api.EvtQuery.restype = ctypes.c_void_p
        self.api.EvtNext.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.POINTER(ctypes.c_void_p), ctypes.c_uint32, ctypes.c_uint32, ctypes.POINTER(ctypes.c_uint32)]
        self.api.EvtNext.restype = ctypes.c_int
        self.api.EvtRender.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32), ctypes.POINTER(ctypes.c_uint32)]
        self.api.EvtRender.restype = ctypes.c_int
        self.api.EvtClose.argtypes = [ctypes.c_void_p]
        self.api.EvtClose.restype = ctypes.c_int

    def query(self, expression="*", reverse=False, limit=256):
        if not self.api:
            raise OSError("Windows Event Log unavailable")
        handle = self.api.EvtQuery(None, SYSMON_CHANNEL, expression, 1 | (0x200 if reverse else 0x100))
        if not handle:
            error = ctypes.get_last_error()
            raise OSError(error, "Sysmon channel is unavailable or access is denied")
        items = []
        try:
            while len(items) < limit:
                handles = (ctypes.c_void_p * min(32, limit - len(items)))()
                returned = ctypes.c_uint32()
                ok = self.api.EvtNext(handle, len(handles), handles, 0, 0, ctypes.byref(returned))
                if not ok:
                    if ctypes.get_last_error() in (259, 1460):
                        break
                    raise OSError(ctypes.get_last_error(), "Windows Event Log read failed")
                for index in range(returned.value):
                    event_handle = handles[index]
                    try:
                        required, count = ctypes.c_uint32(), ctypes.c_uint32()
                        self.api.EvtRender(None, event_handle, 1, 0, None, ctypes.byref(required), ctypes.byref(count))
                        if required.value > 262144:
                            self.store.gap("Oversized Sysmon event skipped.")
                            continue
                        buffer = ctypes.create_unicode_buffer(required.value // ctypes.sizeof(ctypes.c_wchar) + 1)
                        if not self.api.EvtRender(None, event_handle, 1, ctypes.sizeof(buffer), buffer, ctypes.byref(required), ctypes.byref(count)):
                            raise OSError(ctypes.get_last_error(), "Event XML rendering failed")
                        items.append(buffer.value)
                    finally:
                        self.api.EvtClose(event_handle)
        finally:
            self.api.EvtClose(handle)
        return items

    @staticmethod
    def record(xml):
        return int(ET.fromstring(xml).findtext("e:System/e:EventRecordID", "0", NS))

    def poll(self):
        if not self.api:
            return []
        try:
            if not self.initialized:
                latest = self.query(reverse=True, limit=1)
                newest = self.record(latest[0]) if latest else 0
                if self.cursor and newest < self.cursor:
                    self.store.gap("Sysmon log was cleared or replaced; record cursor restarted.")
                    self.epoch = uuid.uuid4().hex
                    self.cursor = 0
                if not self.cursor:
                    self.cursor = newest  # Monitoring begins now; no broad historical telemetry import.
                else:
                    self.store.gap("Sysmon reader reconnected; delayed events are recovered from its saved cursor. Events read but not persisted before a service interruption may have been lost.")
                self.initialized = True
                self.store.set_meta("sysmon_epoch", self.epoch)
            events = []
            for xml in self.query(f"*[System[EventRecordID > {int(self.cursor)}]]", limit=256):
                record = self.record(xml)
                event = parse_sysmon(xml, self.epoch)
                self.cursor = max(self.cursor, record)
                if event:
                    events.append(event)
            self.store.set_meta("sysmon_cursor", self.cursor)
            self.available = True
            self.detail = "Reading the existing Sysmon channel. Per-event configuration is unknown; absence does not prove coverage."
            return events
        except (OSError, ValueError, ET.ParseError) as error:
            if self.available:
                self.store.gap(f"Sysmon reader disconnected: {error}")
            self.available = False
            self.initialized = False
            self.detail = str(error)
            return []

    def find_creation(self, pid, created):
        if not self.api:
            return None
        # A narrowly filtered, bounded ancestry lookup for the explicitly selected root.
        expression = f"*[System[EventID=1] and EventData[Data[@Name='ProcessId']='{int(pid)}']]"
        try:
            for xml in self.query(expression, reverse=True, limit=16):
                event = parse_sysmon(xml, self.epoch)
                actual = datetime.fromisoformat(event["timestamp"]).timestamp()
                if abs(actual - created) < 1.5:
                    return event
        except (OSError, ValueError, ET.ParseError):
            pass
        return None


def process_info(process):
    try:
        with process.oneshot():
            created = process.create_time()
            image = process.exe()
            info = {"pid": process.pid, "ppid": process.ppid(), "name": process.name(),
                    "image": image, "command_line": subprocess_command(process.cmdline()),
                    "created": created, "started_at": timestamp(created),
                    "key": poll_key(process.pid, created), "uncertain": False}
        return info
    except psutil.AccessDenied:
        try:
            created = process.create_time()
            return {"pid": process.pid, "ppid": process.ppid(), "name": process.name(), "image": "",
                    "command_line": "", "created": created, "started_at": timestamp(created),
                    "key": poll_key(process.pid, created), "uncertain": True}
        except psutil.Error:
            return None
    except psutil.Error:
        return None


def subprocess_command(args):
    import subprocess
    return subprocess.list2cmdline(args)[:8192]


def list_processes():
    items = []
    for process in psutil.process_iter():
        value = process_info(process)
        if value:
            items.append({k: v for k, v in value.items() if k not in ("ppid", "created")})
    return sorted(items, key=lambda p: (p["name"].lower(), p["pid"]))[:3000]


def process_snapshot():
    """Get parent IDs once for the entire system; avoid expensive per-process Windows queries."""
    if os.name != "nt":
        return {p.pid: p.info for p in psutil.process_iter(["pid", "ppid", "create_time"])}
    from ctypes import wintypes
    class ProcessEntry(ctypes.Structure):
        _fields_ = [("dwSize", wintypes.DWORD), ("cntUsage", wintypes.DWORD),
                    ("th32ProcessID", wintypes.DWORD), ("th32DefaultHeapID", ctypes.c_size_t),
                    ("th32ModuleID", wintypes.DWORD), ("cntThreads", wintypes.DWORD),
                    ("th32ParentProcessID", wintypes.DWORD), ("pcPriClassBase", wintypes.LONG),
                    ("dwFlags", wintypes.DWORD), ("szExeFile", wintypes.WCHAR * 260)]
    api = ctypes.WinDLL("kernel32", use_last_error=True)
    api.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    api.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    api.Process32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(ProcessEntry)]
    api.Process32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(ProcessEntry)]
    api.CloseHandle.argtypes = [wintypes.HANDLE]
    handle = api.CreateToolhelp32Snapshot(2, 0)
    if handle == ctypes.c_void_p(-1).value:
        raise OSError(ctypes.get_last_error(), "Windows process snapshot failed")
    values = {}
    try:
        entry = ProcessEntry()
        entry.dwSize = ctypes.sizeof(entry)
        success = api.Process32FirstW(handle, ctypes.byref(entry))
        while success:
            values[entry.th32ProcessID] = {"pid": entry.th32ProcessID, "ppid": entry.th32ParentProcessID}
            success = api.Process32NextW(handle, ctypes.byref(entry))
    finally:
        api.CloseHandle(handle)
    return values


class Collector:
    def __init__(self, store, on_events):
        self.store, self.on_events = store, on_events
        self.reader = SysmonReader(store)
        self.queue = queue.Queue(maxsize=16384)
        self.pending = deque(maxlen=4096)
        self.known = {}  # Stable keys of explicit roots and observed descendants; survives parent exits.
        self.seen = {}
        self.connections = set()
        self.lock = threading.RLock()
        self.shutdown_event = threading.Event()
        self.dropped = 0
        self.status = "idle"
        self.network_denied = False
        self.last_poll = 0
        self.last_sysmon = 0
        self.last_prune = 0
        self.poll_thread = threading.Thread(target=self._collect, name="big-brother-collector", daemon=True)
        self.consume_thread = threading.Thread(target=self._consume, name="big-brother-evidence", daemon=True)
        self.poll_thread.start()
        self.consume_thread.start()

    def submit(self, event):
        if self.queue.qsize() >= self.store.get_settings()["max_queue"]:
            self.dropped += 1
            if self.dropped == 1 or self.dropped % 100 == 0:
                self.store.gap(f"Collector queue reached its bound; {self.dropped} events dropped.")
            return False
        try:
            self.queue.put_nowait(event)
            return True
        except queue.Full:
            self.dropped += 1
            return False

    def watch_seed(self, info, live_existing=True):
        key = info["key"]
        with self.lock:
            self.known[key] = info
            self.seen[key] = info
        self.submit({"process_key": key, "pid": info["pid"], "timestamp": info["started_at"],
                     "kind": "process_start", "image": info["image"], "command_line": info["command_line"],
                     "name": info["name"], "source": "polling", "uncertain": bool(live_existing),
                     "details": {"snapshot": True, "observed_at": now(), "ancestry_incomplete": live_existing}})
        creation = self.reader.find_creation(info["pid"], info["created"])
        if creation:
            self.store.alias(creation["process_key"], key)
            self.submit(creation)
        self.status = "collecting"

    def active_keys(self):
        keys = set()
        for session in self.store.sessions():
            if session["mode"] == "live" and session["status"] in ("watching", "paused"):
                keys.update(p["key"] for p in self.store.processes(session["id"]))
                keys.add(session["root_key"])
        return keys

    def _collect(self):
        while not self.shutdown_event.wait(0.1):
            try:
                with self.lock:
                    self._collect_once()
            except Exception as error:
                self.store.gap(f"Collector exception; recovery will be attempted: {type(error).__name__}: {error}")
                self.shutdown_event.wait(1)

    def _collect_once(self):
        active = self.active_keys()
        self.status = "collecting" if active else "idle"
        if not active:
            return
        clock = time.monotonic()
        if clock - self.last_sysmon >= 1:
            self.last_sysmon = clock
            fresh = self.reader.poll()
            for event in fresh:
                if len(self.pending) == self.pending.maxlen:
                    self.dropped += 1
                    if self.dropped == 1 or self.dropped % 100 == 0:
                        self.store.gap("Bounded Sysmon correlation buffer overflowed; unmatched ancestry may be incomplete.")
                self.pending.append(event)
            progress = True
            while progress:
                progress = False
                for event in list(self.pending):
                    key = self.store.resolve(event["process_key"])
                    parent = self.store.resolve(event["parent_key"]) if event.get("parent_key") else None
                    if key in active or parent in active:
                        if event["kind"] == "process_start":
                            try:
                                info = process_info(psutil.Process(event["pid"]))
                                event_created = datetime.fromisoformat(event["timestamp"]).timestamp()
                                if info and abs(info["created"] - event_created) < 1.5:
                                    self.store.alias(event["process_key"], info["key"])
                                    key = info["key"]
                                    self.known[key] = info
                            except psutil.Error:
                                pass
                        self.submit(event)
                        active.add(key)
                        self.pending.remove(event)
                        progress = True
        if clock - self.last_poll >= self.store.get_settings()["poll_interval"]:
            self.last_poll = clock
            self.poll_snapshot(active)
        if clock - self.last_prune >= 60:
            self.last_prune = clock
            self.store.prune()

    def flush(self, timeout=4):
        deadline = time.monotonic() + timeout
        with self.queue.all_tasks_done:
            while self.queue.unfinished_tasks:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    self.store.gap("Stop deadline reached before queued events finished; some evidence may be incomplete.")
                    return False
                self.queue.all_tasks_done.wait(remaining)
        return True

    def poll_snapshot(self, active=None):
        active = active or self.active_keys()
        snapshots = process_snapshot()
        selected = set()
        def identify(pid):
            value = snapshots[pid]
            if "key" not in value:
                created = value.get("create_time") or psutil.Process(pid).create_time()
                value.update({"create_time": created, "key": poll_key(pid, created)})
            return value
        # Validate the current creation time before treating any reused PID as a watched node.
        candidates = {info["pid"] for key, info in list(self.known.items()) if self.store.resolve(key) in active}
        for key in active:
            if not key.startswith("poll:"):
                value = self.store.process(key)
                if value:
                    candidates.add(value["pid"])
        for pid in candidates.intersection(snapshots):
            try:
                value = identify(pid)
                if self.store.resolve(value["key"]) in active:
                    selected.add(pid)
            except psutil.Error:
                pass
        changed = True
        while changed:
            changed = False
            for pid, value in snapshots.items():
                if pid in selected:
                    continue
                parent = snapshots.get(value["ppid"])
                if not parent or parent["pid"] not in selected:
                    continue
                try:
                    value = identify(pid)
                except psutil.Error:
                    continue
                if parent["create_time"] <= value["create_time"]:
                    selected.add(pid)
                    active.add(value["key"])
                    changed = True
        seen_now = {}
        connections_now = set()
        for pid in selected:
            value = snapshots[pid]
            key = value["key"]
            previous = self.known.get(key)
            info = previous or process_info(psutil.Process(pid))
            if not info or info["key"] != key:
                continue
            seen_now[key] = info
            if key not in self.seen:
                parent = snapshots.get(value["ppid"])
                parent_key = parent["key"] if parent and parent["pid"] in selected else None
                self.submit({"process_key": key, "parent_key": parent_key, "pid": pid, "timestamp": info["started_at"],
                             "kind": "process_start", "image": info["image"], "command_line": info["command_line"],
                             "source": "polling", "uncertain": True, "details": {"snapshot": True}})
                self.known[key] = info
            try:
                process = psutil.Process(pid)
                for connection in process.net_connections(kind="inet"):
                    if not connection.raddr:
                        continue
                    identity = (key, connection.laddr.ip, connection.laddr.port, connection.raddr.ip, connection.raddr.port, connection.status)
                    connections_now.add(identity)
                    if identity not in self.connections and process.create_time() == info["created"]:
                        self.submit({"process_key": key, "pid": pid, "timestamp": now(), "kind": "network",
                                     "image": info["image"], "source": "polling", "uncertain": True,
                                     "details": {"destination_ip": connection.raddr.ip, "destination_port": connection.raddr.port,
                                                 "local_ip": connection.laddr.ip, "local_port": connection.laddr.port,
                                                 "status": connection.status, "snapshot": True,
                                                 "direction": "unknown", "protocol": "tcp" if connection.type == 1 else "udp"}})
            except psutil.AccessDenied:
                self.network_denied = True
            except psutil.Error:
                pass
        for key, info in list(self.seen.items()):
            if key not in seen_now and self.store.resolve(key) in active:
                info["ended_observed"] = time.time()
                self.submit({"process_key": key, "pid": info["pid"], "timestamp": now(), "kind": "process_end",
                             "image": info["image"], "source": "polling", "uncertain": True,
                             "details": {"snapshot": True, "termination_time_approximate": True}})
        self.seen = seen_now
        self.connections = connections_now
        # Expired roots are no longer queried; membership in the database still preserves surviving descendants.
        if len(self.known) > 10000:
            self.known = {k: v for k, v in self.known.items() if k in active}

    def _consume(self):
        while not self.shutdown_event.is_set() or not self.queue.empty():
            try:
                first = self.queue.get(timeout=0.2)
            except queue.Empty:
                continue
            batch = [first]
            for _ in range(127):
                try:
                    batch.append(self.queue.get_nowait())
                except queue.Empty:
                    break
            modified = False
            for event in batch:
                try:
                    modified = self.store.ingest(event) or modified
                except Exception as error:
                    self.store.gap(f"Malformed event skipped: {type(error).__name__}: {error}")
                finally:
                    self.queue.task_done()
            if modified:
                self.store.prune()
                try:
                    self.on_events()
                except Exception as error:
                    self.store.gap(f"Analysis unavailable: {type(error).__name__}: {error}")

    def state(self):
        return {"status": self.status, "backend": "polling+sysmon" if self.reader.available else "polling",
                "gaps": self.store.gaps(), "dropped_events": self.dropped, "queue_depth": self.queue.qsize(),
                "sysmon_detail": self.reader.detail}

    def coverage(self):
        configured = self.reader.available
        values = [{"kind": "processes", "status": "partial", "backend": "polling",
                   "detail": "Process snapshots and creation-time identities. Short-lived children between polls can be missed; ancestry before watch may be incomplete."},
                  {"kind": "network", "status": "partial", "backend": "polling",
                   "detail": "Connection snapshots only. Brief connections, DNS and traffic contents are unavailable. Some protected processes deny access."}]
        for kind in ("processes", "network", "dns", "files", "registry", "process_access", "remote_thread", "image_load"):
            values.append({"kind": kind, "status": "configuration_unknown" if configured else "unavailable", "backend": "sysmon",
                           "detail": "Existing channel readable; event filters may exclude activity. Coverage is not guaranteed." if configured else self.reader.detail})
        values.append({"kind": "file_reads_and_encrypted_contents", "status": "unavailable", "backend": "all",
                       "detail": "Complete file reads, full command history and encrypted traffic contents are not collected."})
        return values

    def close(self):
        self.shutdown_event.set()
        self.poll_thread.join(timeout=5)
        self.consume_thread.join(timeout=5)
        if self.poll_thread.is_alive() or self.consume_thread.is_alive():
            self.store.gap("Shutdown deadline reached; unfinished collection may be lost.")
        self.status = "stopped"
