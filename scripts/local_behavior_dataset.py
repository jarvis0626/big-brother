"""Make an explicit local diagnostic holdout without exporting private evidence.

This is a separate research format, not an app recording or model-training input.
The selected live session is read through SQLite's read-only URI mode. Only event
order, event categories and capture-local process relationships leave the store.
Output stays in this checkout's ignored training/data/v3/local directory. No
network calls, fitting, calibration, threshold changes or automatic uploads occur.

Usage: python scripts/local_behavior_dataset.py --database PATH --session ID
The command prints aggregate counts only; it never prints the selected ID, input
path, generated filename, raw evidence or underlying exception text.
"""
from __future__ import annotations

import argparse
import collections
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import sqlite3
import sys
import time
import uuid


ROOT = Path(__file__).resolve().parents[1]
MAX_EVENTS = 20_000
MAX_PROCESSES = 1_000
MAX_DETAILS_BYTES = 32_768
MAX_INPUT_BYTES = 16 * 1024 * 1024
MAX_ORDER_FIELD_LENGTH = 128
ROLE = "diagnostic_holdout"
LABEL = "user_reported_expected"
KINDS = frozenset({"process_start", "process_end", "network", "dns", "file_create",
                   "file_delete", "registry", "process_access", "remote_thread",
                   "image_load", "raw_access"})
SOURCES = frozenset({"polling", "sysmon", "recording", "unknown"})
TCP_STATUSES = frozenset({"ESTABLISHED", "SYN_SENT", "SYN_RECV", "FIN_WAIT1", "FIN_WAIT2",
                          "TIME_WAIT", "CLOSE", "CLOSE_WAIT", "LAST_ACK", "LISTEN",
                          "CLOSING", "NONE", "UNKNOWN", "NOT_APPLICABLE"})
PORT_CATEGORIES = frozenset({"web", "smb", "remote", "dns", "other_service", "high_port", "unknown"})


class DatasetError(ValueError):
    """A deliberately generic error safe for display and command logs."""


class _PrivateArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        # argparse normally repeats invalid argument values, which might contain
        # local paths or selected session IDs.
        raise DatasetError("Explicit database, session and valid event-bound arguments are required.")


def _output_directory(output_dir: Path | None) -> Path:
    # Do not follow a junction/symlink in the fixed ignored-data ancestry outside
    # this checkout. A caller cannot choose an arbitrary export destination.
    base = ROOT.resolve() / "training" / "data" / "v3" / "local"
    if base.resolve() != base:
        raise DatasetError("The local dataset directory must remain inside the checkout.")
    destination = Path(output_dir) if output_dir is not None else base
    if not destination.is_absolute():
        raise DatasetError("The local dataset destination must be absolute.")
    destination = destination.resolve()
    if not destination.is_relative_to(base):
        raise DatasetError("The local dataset destination must remain in the ignored local dataset directory.")
    return destination


def _port_category(value) -> str:
    if isinstance(value, bool):
        return "unknown"
    if isinstance(value, int):
        port = value
    elif isinstance(value, str) and re.fullmatch(r"[0-9]{1,5}", value):
        port = int(value)
    else:
        return "unknown"
    if not 0 <= port <= 65535:
        return "unknown"
    if port in {80, 443, 8080, 8443}:
        return "web"
    if port in {139, 445}:
        return "smb"
    if port in {22, 3389}:
        return "remote"
    if port == 53:
        return "dns"
    return "other_service" if port < 1024 else "high_port"


def _source(value) -> str:
    if value in {"polling", "sysmon"}:
        return value
    if isinstance(value, str) and value.startswith("recording:"):
        return "recording"
    return "unknown"


def _details(value) -> dict:
    if not isinstance(value, str) or len(value.encode("utf-8")) > MAX_DETAILS_BYTES:
        raise DatasetError("Selected evidence exceeds the local diagnostic limits.")
    parsed = json.loads(value)
    if not isinstance(parsed, dict):
        raise DatasetError("Selected evidence has an unsupported structure.")
    return parsed


def _observation_order(row):
    # SQLite's text order disagrees with chronology for mixed fractional ISO
    # timestamps and UTC offsets. Neither timestamp nor event ID is exported.
    value, event_id = row["timestamp"], row["id"]
    if (not isinstance(value, str) or not 1 <= len(value) <= MAX_ORDER_FIELD_LENGTH or
            not isinstance(event_id, str) or not 1 <= len(event_id) <= MAX_ORDER_FIELD_LENGTH):
        raise DatasetError("Selected evidence has invalid or oversized ordering fields.")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        parsed = parsed.astimezone(timezone.utc) if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    except (ValueError, TypeError, OverflowError):
        raise DatasetError("Selected evidence has invalid ordering timestamps.") from None
    return parsed, event_id


def _safe_event(row, order, identities, parent_by_key) -> dict:
    kind = row["kind"]
    if kind not in KINDS:
        raise DatasetError("Selected evidence contains an unsupported event category.")
    details = _details(row["details"])
    parent = row["parent_key"] or parent_by_key.get(row["process_key"])
    result = {"order": order, "process": identities[row["process_key"]],
              "parent": identities.get(parent), "kind": kind,
              "source": _source(row["source"]), "snapshot": details.get("snapshot") is True,
              "uncertain": row["uncertain"] != 0}
    if kind == "network":
        result["destination_port_category"] = _port_category(details.get(
            "destination_port", details.get("dest_port", details.get("remote_port"))))
        protocol = details.get("protocol", details.get("Protocol"))
        protocol = protocol.lower() if isinstance(protocol, str) else "unknown"
        result["protocol"] = protocol if protocol in {"tcp", "udp"} else "unknown"
        status = details.get("status")
        status = status.upper() if isinstance(status, str) else "UNKNOWN"
        result["tcp_status"] = ("NOT_APPLICABLE" if result["protocol"] == "udp" else
                                status if status in TCP_STATUSES else "UNKNOWN")
    return result


def _assert_safe_payload(payload: dict) -> None:
    """Fail closed if a later edit accidentally adds a raw-evidence field."""
    if set(payload) != {"schema", "capture", "role", "label", "fit_eligible", "calibration_eligible",
                        "automatic_upload", "notice", "processes", "events"}:
        raise DatasetError("The diagnostic privacy schema check failed.")
    if payload["role"] != ROLE or payload["label"] != LABEL or any(
            payload[key] is not False for key in ("fit_eligible", "calibration_eligible", "automatic_upload")):
        raise DatasetError("Diagnostic cases cannot enter fitting or calibration.")
    if not re.fullmatch(r"capture_[0-9a-f]{32}", payload["capture"]):
        raise DatasetError("The capture identity must be local and generated.")
    identities = {p["identity"] for p in payload["processes"]}
    if any(not re.fullmatch(r"p[1-9][0-9]*", identity) for identity in identities):
        raise DatasetError("Process identities must be capture-local.")
    for process in payload["processes"]:
        if set(process) != {"identity", "parent"} or process["parent"] not in identities | {None}:
            raise DatasetError("The process privacy schema check failed.")
    required = {"order", "process", "parent", "kind", "source", "snapshot", "uncertain"}
    for index, event in enumerate(payload["events"]):
        fields = required | ({"destination_port_category", "protocol", "tcp_status"}
                             if event["kind"] == "network" else set())
        if (set(event) != fields or event["order"] != index or event["process"] not in identities or
                event["parent"] not in identities | {None} or event["kind"] not in KINDS or
                event["source"] not in SOURCES or type(event["snapshot"]) is not bool or
                type(event["uncertain"]) is not bool):
            raise DatasetError("The event privacy schema check failed.")
        if event["kind"] == "network" and (event["destination_port_category"] not in PORT_CATEGORIES or
                event["protocol"] not in {"tcp", "udp", "unknown"} or event["tcp_status"] not in TCP_STATUSES):
            raise DatasetError("Network fields must contain only coarse categories.")


def _read_selected(database: Path, session: str, limit: int) -> tuple[list, list]:
    connection = None
    try:
        connection = sqlite3.connect(database.as_uri() + "?mode=ro", uri=True, timeout=1)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA query_only=ON")
        connection.execute("PRAGMA trusted_schema=OFF")
        # One read-only snapshot covers session selection, membership and event
        # rows while another app instance may still be collecting evidence.
        connection.execute("BEGIN")
        deadline = time.monotonic() + 15
        connection.set_progress_handler(lambda: int(time.monotonic() > deadline), 1_000)
        selected = connection.execute("SELECT mode FROM sessions WHERE id=?", (session,)).fetchone()
        if selected is None or selected["mode"] != "live":
            raise DatasetError("Select one existing live-observation session explicitly.")
        processes = connection.execute("""SELECT m.process_key, p.parent_key FROM membership m
            LEFT JOIN processes p ON p.key=m.process_key WHERE m.session_id=?
            ORDER BY m.process_key LIMIT ?""", (session, MAX_PROCESSES + 1)).fetchall()
        if not processes or len(processes) > MAX_PROCESSES:
            raise DatasetError("Selected evidence exceeds the local diagnostic limits.")
        rows = []
        input_bytes = 0
        for row in connection.execute("""SELECT e.process_key,e.parent_key,e.kind,
                substr(e.details,1,32769) details,e.source,e.uncertain,
                substr(e.timestamp,1,129) timestamp,substr(e.id,1,129) id
            FROM events e JOIN membership m ON m.process_key=e.process_key
            JOIN sessions s ON s.id=m.session_id
            WHERE m.session_id=? AND (s.ended_at IS NULL OR e.ingested_at <= s.ended_at)
            LIMIT ?""", (session, limit + 1)):
            rows.append(row)
            input_bytes += len(row["details"].encode("utf-8")) if isinstance(row["details"], str) else MAX_INPUT_BYTES
            if len(rows) > limit or input_bytes > MAX_INPUT_BYTES:
                raise DatasetError("Selected evidence exceeds the local diagnostic limits; no truncated dataset was written.")
        if not rows:
            raise DatasetError("The selected session has no recorded events.")
        return processes, sorted(rows, key=_observation_order)
    except DatasetError:
        raise
    except Exception:
        raise DatasetError("The selected local evidence could not be read safely.") from None
    finally:
        if connection is not None:
            connection.close()


def export_local_holdout(database: Path, session: str, *, output_dir: Path | None = None,
                         max_events: int = MAX_EVENTS, role: str = ROLE, label: str = LABEL) -> dict:
    """Return only aggregate facts; the selected session is never printed or returned."""
    if role != ROLE or label != LABEL:
        raise DatasetError("Only user-reported diagnostic holdouts are supported; they cannot be used for fitting or calibration.")
    if type(max_events) is not int or not 1 <= max_events <= MAX_EVENTS:
        raise DatasetError("The event bound must be an integer within the local diagnostic limits.")
    if not isinstance(session, str) or re.fullmatch(r"[A-Za-z0-9_-]{1,128}", session) is None:
        raise DatasetError("Select one existing live-observation session explicitly.")
    database = Path(database)
    if not database.is_absolute() or not database.is_file():
        raise DatasetError("Select an existing local evidence database explicitly.")
    destination = _output_directory(output_dir)
    processes, rows = _read_selected(database.resolve(), session, max_events)
    parent_by_key = {row["process_key"]: row["parent_key"] for row in processes}
    # First event order makes identities meaningful within this one capture only.
    keys = dict.fromkeys([row["process_key"] for row in rows] + list(parent_by_key))
    identities = {key: f"p{index + 1}" for index, key in enumerate(keys)}
    try:
        events = [_safe_event(row, index, identities, parent_by_key) for index, row in enumerate(rows)]
        payload = {"schema": "big-brother-local-behavior-holdout-v1", "capture": "capture_" + uuid.uuid4().hex,
                   "role": role, "label": label, "fit_eligible": False, "calibration_eligible": False,
                   "automatic_upload": False,
                   "notice": "User-reported expected activity is not independently verified benign ground truth. "
                             "This diagnostic case is excluded from fitting, calibration and threshold selection. "
                             "Coarse event sequences can remain identifying; keep this file local.",
                   "processes": [{"identity": identities[key], "parent": identities.get(parent_by_key.get(key))}
                                 for key in keys], "events": events}
        _assert_safe_payload(payload)
        encoded = json.dumps(payload, ensure_ascii=True, indent=2) + "\n"
    except DatasetError:
        raise
    except Exception:
        raise DatasetError("Selected evidence could not pass the diagnostic privacy schema.") from None
    target = None
    created = False
    try:
        destination.mkdir(parents=True, exist_ok=True)
        destination = _output_directory(destination)
        target = destination / (payload["capture"] + ".json")
        with target.open("x", encoding="utf-8", newline="\n") as stream:
            created = True
            stream.write(encoded)
    except DatasetError:
        raise
    except Exception:
        if created and target is not None:
            try:
                target.unlink(missing_ok=True)
            except OSError:
                pass
        raise DatasetError("The local diagnostic dataset could not be saved.") from None
    return {"events": len(events), "processes": len(identities), "role": role, "label": label,
            "kind_counts": dict(collections.Counter(event["kind"] for event in events)),
            "privacy_schema_passed": True, "raw_identifiers_exported": False,
            "fit_eligible": False, "calibration_eligible": False, "automatic_upload": False}


def main(argv=None) -> int:
    parser = _PrivateArgumentParser(description="Create a local, privacy-reduced diagnostic holdout from one explicitly selected live session.")
    parser.add_argument("--database", type=Path, required=True, help="Existing Big Brother SQLite evidence database")
    parser.add_argument("--session", required=True, help="One explicit live-observation session ID; never printed")
    parser.add_argument("--max-events", type=int, default=MAX_EVENTS)
    try:
        args = parser.parse_args(argv)
        summary = export_local_holdout(args.database, args.session, max_events=args.max_events)
    except DatasetError as error:
        print(json.dumps({"error": str(error)}), file=sys.stderr)
        return 1
    except Exception:
        # Filesystem resolution/open errors may include complete private paths.
        print(json.dumps({"error": "The local diagnostic request could not be completed safely."}), file=sys.stderr)
        return 1
    print(json.dumps(summary, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
