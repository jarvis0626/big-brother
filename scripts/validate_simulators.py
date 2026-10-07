"""Observe real harmless Windows executables through the production collector.

Only aggregate experimental results are exported. Raw captured process evidence
stays in a disposable D: scratch SQLite database and is never committed.
"""
from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import psutil
from backend.service import Application
from scripts.simulators.behavior_app import RunWorkspace, MARKER
from scripts.simulators.build import NAMES


def trace_records(directory):
    records = []
    for path in directory.glob("trace-*.jsonl"):
        for line in path.read_text(encoding="utf-8").splitlines():
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                pass  # An actively written final line will be retried next poll.
    return records


def runtime_complete(scenario, records):
    parent_done = any(row["action"] == "parent_completed" for row in records)
    roles = {row.get("role") for row in records if row["action"] == "work_completed"}
    required = {"ordinary"} if scenario == "ordinary" else ({"fanout-parent", "helper-0", "helper-1", "helper-2"}
                                                            if scenario == "fanout" else {"surviving-helper"})
    return parent_done and required.issubset(roles)


def validate_one(app, scenario, executable):
    runs_root = executable.parent / "simulator-runs"
    previous = {path.name for path in runs_root.glob("bb-simulator-*")} if runs_root.exists() else set()
    session = app.launch(str(executable.resolve()))  # Same selected-.exe production API as the Electron dialog.
    started = time.monotonic()
    directory = None
    records = []
    deadline = started + 45
    try:
        while time.monotonic() < deadline:
            new_runs = [path for path in runs_root.glob("bb-simulator-*") if path.name not in previous]
            if len(new_runs) > 1:
                raise RuntimeError("A concurrent simulator run prevents unambiguous attribution")
            if new_runs:
                directory = new_runs[0]
                records = trace_records(directory)
                if runtime_complete(scenario, records):
                    break
            time.sleep(.2)
        else:
            raise RuntimeError(f"{scenario}: simulator did not finish its bounded workload")
        # Let real exit/network snapshots settle; do not inject any events or alter thresholds.
        time.sleep(2)
        state = app.stop(session["id"])
        events = state["events"]
        model_result = app.model.score(events)
        actual_runtime_pids = {row["pid"] for row in records if row["action"] in ("parent_started", "work_started")}
        observed_pids = {process["pid"] for process in state["processes"]}
        evidence_ids = {event["id"] for event in events}
        findings = state["incidents"]
        factual_ids_valid = all(set(fact["event_ids"]).issubset(evidence_ids) and fact["event_ids"]
                               for finding in findings for fact in finding["explanation"]["observed"])
        loopback_only = all(str(event["details"].get("destination_ip")) in ("127.0.0.1", "::1")
                            for event in events if event["kind"] == "network")
        if not actual_runtime_pids.issubset(observed_pids):
            raise AssertionError(f"{scenario}: an actual trusted runtime process was not attributed")
        if not any(event["kind"] == "network" for event in events):
            raise AssertionError(f"{scenario}: no held-open real loopback connection was observed")
        if not factual_ids_valid or not loopback_only:
            raise AssertionError("Invalid finding evidence or non-loopback experimental destination")
        if state["model"]["status"] != "available" or model_result["status"] not in ("available", "insufficient_evidence"):
            raise AssertionError("A genuine trained model was not available")
        if any(event["source"].startswith("replay") or event["details"].get("fabricated") for event in events):
            raise AssertionError("Fabricated telemetry contaminated the live experimental session")
        survives = any(finding["title"] == "A child continued connecting after its parent ended" for finding in findings)
        if scenario == "survivor" and not survives:
            raise AssertionError("Real surviving-child behavior did not reach the transparent reference rule")
        return {
            "scenario": scenario, "passed": True, "elapsed_seconds": round(time.monotonic() - started, 3),
            "executable": executable.name, "executable_sha256": hashlib.sha256(executable.read_bytes()).hexdigest(),
            "session_mode": state["session"]["mode"], "actual_events": len(events),
            "event_kinds": dict(Counter(event["kind"] for event in events)),
            "event_sources": dict(Counter(event["source"] for event in events)),
            "observed_processes": len(observed_pids), "actual_runtime_processes": len(actual_runtime_pids),
            "all_runtime_processes_attributed": True, "only_loopback_network": loopback_only,
            "scratch_files_actually_created": sum(row.get("count", 0) for row in records if row["action"] == "scratch_files_created"),
            "scratch_file_events_observed": sum(event["kind"] == "file_create" for event in events),
            "loopback_exchanges_actually_completed": sum(row.get("exchanges", 0) for row in records if row["action"] == "work_completed"),
            "transparent_rule_findings": sum(finding["score_kind"] == "rule_reference" for finding in findings),
            "model_findings": sum(finding["score_kind"] != "rule_reference" for finding in findings),
            "surviving_child_rule_observed": survives, "finding_citations_valid": factual_ids_valid,
            "model": {"version": model_result["model_version"], "artifact_sha256": state["model"]["artifact_sha256"],
                      "status": model_result["status"], "score_nats": model_result["score"],
                      "threshold": model_result["threshold"], "above_threshold": model_result["above_threshold"],
                      "features": model_result.get("features", {}), "limitations": model_result["limitations"]},
            "collector_backend": state["collector"]["backend"], "collector_dropped_events": state["collector"]["dropped_events"],
            "coverage": state["coverage"], "no_raw_telemetry_exported": True,
        }
    finally:
        if directory and directory.exists():
            marker = json.loads((directory / MARKER).read_text(encoding="utf-8"))
            workspace = RunWorkspace(directory, marker["token"])
            # A failure may leave bounded children briefly active. Wait for only
            # processes whose trusted simulator command line names this exact run.
            own = []
            for process in psutil.process_iter(["pid", "exe", "cmdline"]):
                try:
                    if (process.info["exe"] and Path(process.info["exe"]).resolve() == executable.resolve()
                            and str(directory) in process.info["cmdline"]):
                        own.append(process)
                except (psutil.Error, OSError):
                    pass
            _, pending = psutil.wait_procs(own, timeout=30)
            if pending:
                raise RuntimeError("Owned simulator children did not meet their duration bound; files preserved")
            workspace.clean()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "artifacts" / "simulator-validation-v2.json")
    args = parser.parse_args()
    if os.name != "nt":
        parser.error("This validation requires the real Windows process collector")
    release = ROOT / "release" / "simulators"
    missing = [name for name in NAMES.values() if not (release / name).is_file()]
    if missing:
        parser.error("Build the simulators first: .venv\\Scripts\\python.exe scripts\\simulators\\build.py")
    cache = ROOT / ".cache" / "simulator-validation"
    cache.mkdir(parents=True, exist_ok=True)
    results = {"schema": 1, "measured_at_utc": datetime.now(timezone.utc).isoformat(),
               "purpose": "Harmless live collector engineering validation; not malware detection accuracy",
               "thresholds_unchanged": True, "no_fabricated_events_in_live_sessions": True,
               "limitations": [
                   "These programs are known benign and are not representative labeled malware samples.",
                   "No finding does not establish safety. An unusual-model finding on a benign simulator is not proof of danger.",
                   "Passing process attribution and connection tests does not validate attack detection recall.",
                   "Polling sees connection/process snapshots; scratch file operations and localhost resolution may be absent.",
                   "One-file bootloader processes are included in real observed lineage.",
                   "No Registry persistence, encryption, credential access, remote command or Defender setting was exercised.",
               ], "scenarios": []}
    with tempfile.TemporaryDirectory(prefix="owned-validation-", dir=cache) as data:
        app = Application(ROOT / "resources", Path(data))
        try:
            for scenario, filename in NAMES.items():
                result = validate_one(app, scenario, release / filename)
                results["scenarios"].append(result)
                print(json.dumps({"scenario": scenario, "passed": result["passed"],
                                  "events": result["actual_events"], "model_score_nats": result["model"]["score_nats"],
                                  "above_threshold": result["model"]["above_threshold"],
                                  "rule_findings": result["transparent_rule_findings"]}), flush=True)
        finally:
            app.close()
    results["passed"] = all(row["passed"] for row in results["scenarios"])
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(results, indent=2), encoding="utf-8")
    print(f"Aggregate validation written to {args.output}")


if __name__ == "__main__":
    main()
