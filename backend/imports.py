"""Bounded inert capture imports; recorded commands and scenario labels are data."""
import hashlib
import json
from pathlib import Path
from backend.storage import timestamp

MAX_BYTES = 32 * 1024 * 1024
MAX_EVENTS = 10000
KINDS = {"process_start", "process_end", "network", "dns", "file_create", "file_delete", "registry", "process_access", "image_load", "remote_thread"}
FIELDS = {"process_key", "parent_key", "pid", "timestamp", "kind", "image", "command_line", "details", "source", "source_record_id", "uncertain"}

def text(value, size, required=False):
    if not isinstance(value, str) or len(value) > size or (required and not value):
        raise ValueError("Invalid or oversized recording string")
    return value

def bounded(value, size, depth=0):
    if depth > 12:
        raise ValueError("Recording nesting exceeds its limit")
    if isinstance(value, dict):
        for key, child in value.items():
            text(key, 256)
            bounded(child, size, depth + 1)
    elif isinstance(value, list):
        for child in value:
            bounded(child, size, depth + 1)
    elif isinstance(value, str):
        text(value, 8192)
    if depth == 0 and len(json.dumps(value, allow_nan=False).encode("utf8")) > size:
        raise ValueError("Recording value exceeds its size limit")
    return value

def load_recording(path):
    path = Path(path)
    if not path.is_absolute() or path.suffix.lower() != ".json" or not path.is_file():
        raise ValueError("Choose an existing normalized recording JSON file")
    with path.open("rb") as source:
        data = source.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise ValueError("Recording exceeds the 32 MiB limit")
    try:
        raw = json.loads(data.decode("utf-8-sig"), parse_constant=lambda _: (_ for _ in ()).throw(ValueError("Nonfinite JSON")))
    except (UnicodeError, RecursionError, json.JSONDecodeError) as error:
        raise ValueError("Recording must contain bounded valid UTF-8 JSON") from error
    if not isinstance(raw, dict) or set(raw) - {"format", "fabricated", "name", "provenance", "coverage", "events"}:
        raise ValueError("Unsupported recording envelope")
    if raw.get("format") != "big-brother-recording-v1" or raw.get("fabricated") is not False:
        raise ValueError("Recording must explicitly declare non-fabricated provenance")
    name = text(raw.get("name"), 200, True)
    provenance = raw.get("provenance")
    coverage = raw.get("coverage", {})
    if not isinstance(provenance, dict) or not provenance.get("dataset") or not isinstance(coverage, dict):
        raise ValueError("Recording must declare dataset provenance and valid coverage")
    bounded(provenance, 16384); bounded(coverage, 8192)
    events = raw.get("events")
    if not isinstance(events, list) or not 1 <= len(events) <= MAX_EVENTS:
        raise ValueError("Recording must contain 1–10,000 events; select a bounded interval")
    validated = []
    for event in events:
        if not isinstance(event, dict) or set(event) - FIELDS or not isinstance(event.get("kind"), str) or event["kind"] not in KINDS:
            raise ValueError("Unsupported recording event fields or kind")
        key = text(event.get("process_key"), 512, True)
        parent = event.get("parent_key")
        if parent is not None: text(parent, 512, True)
        pid = event.get("pid", 0)
        if isinstance(pid, bool) or not isinstance(pid, int) or not 0 <= pid <= 2147483647:
            raise ValueError("Invalid recording process ID")
        stamp = timestamp(text(event.get("timestamp"), 64, True))
        details = event.get("details", {})
        if not isinstance(details, dict): raise ValueError("Invalid recording details")
        bounded(details, 32768)
        uncertain = event.get("uncertain", False)
        if not isinstance(uncertain, bool): raise ValueError("Invalid uncertainty flag")
        source_id = event.get("source_record_id")
        if source_id is not None: text(source_id, 512)
        validated.append({"process_key": key, "parent_key": parent, "pid": pid, "timestamp": stamp,
                          "kind": event["kind"], "details": details, "uncertain": uncertain,
                          "image": text(event.get("image", ""), 4096),
                          "command_line": text(event.get("command_line", ""), 8192),
                          "source": text(event.get("source", "recording"), 512), "source_record_id": source_id})
    keys = {event["process_key"] for event in validated}
    return {"name": name, "events": validated, "event_count": len(validated),
            "provenance": {**provenance, "imported_file_sha256": hashlib.sha256(data).hexdigest(),
                           "provenance_status": "Declared source metadata; import does not authenticate ground truth."},
            "coverage": {**coverage, "unresolved_parent_event_count": sum(bool(e["parent_key"] and e["parent_key"] not in keys) for e in validated)}}
