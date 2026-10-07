"""A harmless standalone process/file/loopback workload, never malware.

Each run modifies only a newly created, token-marked scratch directory. Child
processes execute this same trusted program. No shell, Registry, encryption,
external destination, credential access, or startup configuration is used.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import sys
import threading
import time
import uuid

SCENARIOS = ("ordinary", "fanout", "survivor")
MARKER = ".big-brother-simulator.json"
MAX_FILES = 48
TOKEN_PATTERN = re.compile(r"^[0-9a-f]{32}$")


def valid_token(token):
    if not isinstance(token, str) or not TOKEN_PATTERN.fullmatch(token):
        raise ValueError("Run token must be a generated 32-character hexadecimal ID")
    return token


def is_reparse(path):
    stat = path.lstat()
    return path.is_symlink() or bool(getattr(stat, "st_file_attributes", 0) & 0x400)


class RunWorkspace:
    """Only a generated direct child with a matching ownership marker is writable."""

    def __init__(self, directory, token):
        self.token = valid_token(token)
        supplied = Path(directory).absolute()
        if is_reparse(supplied):
            raise ValueError("A simulator run directory cannot be a link or junction")
        self.path = supplied.resolve(strict=True)
        if self.path.name != f"bb-simulator-{self.token}":
            raise ValueError("Run directory name does not match its ownership token")
        marker_path = self.path / MARKER
        if is_reparse(marker_path):
            raise ValueError("A simulator ownership marker cannot be a link")
        marker = json.loads(marker_path.read_text(encoding="utf-8"))
        if marker != {"schema": 1, "token": self.token, "purpose": "harmless Big Brother simulator"}:
            raise ValueError("Simulator ownership marker is missing or incompatible")

    @classmethod
    def create(cls, parent):
        parent = Path(parent).absolute()
        parent.mkdir(parents=True, exist_ok=True)
        if is_reparse(parent):
            raise ValueError("Scratch root cannot be a link or junction")
        parent = parent.resolve(strict=True)
        token = uuid.uuid4().hex
        directory = parent / f"bb-simulator-{token}"
        directory.mkdir()  # Never reuse or overwrite an existing directory.
        (directory / MARKER).write_text(json.dumps({
            "schema": 1, "token": token, "purpose": "harmless Big Brother simulator"
        }), encoding="utf-8")
        return cls(directory, token)

    def file(self, filename):
        if (not isinstance(filename, str) or not re.fullmatch(r"[A-Za-z0-9._-]{1,96}", filename)
                or Path(filename).name != filename or filename in (".", "..", MARKER)):
            raise ValueError("Only a single owned scratch filename is allowed")
        target = self.path / filename
        if target.exists() and is_reparse(target):
            raise ValueError("Simulator files cannot be links or junctions")
        if target.resolve().parent != self.path:
            raise ValueError("Scratch filename escapes the run directory")
        return target

    def record(self, action, **details):
        with self.file(f"trace-{os.getpid()}.jsonl").open("a", encoding="utf-8") as stream:
            stream.write(json.dumps({"time_ns": time.time_ns(), "pid": os.getpid(), "action": action, **details}) + "\n")

    def clean(self):
        # Revalidate ownership and refuse links anywhere before recursive removal.
        RunWorkspace(self.path, self.token)
        for base, dirs, files in os.walk(self.path, followlinks=False):
            for name in dirs + files:
                if is_reparse(Path(base) / name):
                    raise ValueError("Refusing cleanup of a run containing a link or junction")
        shutil.rmtree(self.path)


def connect_loopback(address):
    host, port = address
    if not ipaddress.ip_address(host).is_loopback or not isinstance(port, int) or not 1 <= port <= 65535:
        raise ValueError("Simulator network destinations must be numeric loopback addresses")
    return socket.create_connection((host, port), timeout=2)


class LoopbackEcho:
    def __init__(self):
        self.stop = threading.Event()
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(8)
        self.listener.settimeout(.2)
        self.address = self.listener.getsockname()
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self):
        while not self.stop.is_set():
            try:
                connection, _ = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            with connection:
                connection.settimeout(.2)
                while not self.stop.is_set():
                    try:
                        data = connection.recv(1024)
                        if not data:
                            break
                        connection.sendall(data)
                    except socket.timeout:
                        continue
                    except OSError:
                        break

    def close(self):
        self.stop.set()
        self.listener.close()
        self.thread.join(timeout=2)


def same_program():
    if getattr(sys, "frozen", False):
        return [sys.executable]
    return [sys.executable, str(Path(__file__).resolve())]


def spawn_child(workspace, role, duration):
    args = same_program() + ["--child", "--run-dir", str(workspace.path), "--token", workspace.token,
                             "--role", role, "--duration", str(duration)]
    process = subprocess.Popen(args, shell=False, stdin=subprocess.DEVNULL,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                               creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)
    workspace.record("child_spawned", child_pid=process.pid, role=role, duration=duration)
    return process


def bounded_work(workspace, duration, role, file_count):
    if not isinstance(file_count, int) or not 0 <= file_count <= MAX_FILES:
        raise ValueError("Scratch file count exceeds the simulator bound")
    workspace.record("work_started", role=role, duration=duration)
    # localhost resolution never intentionally queries an external hostname.
    socket.getaddrinfo("localhost", 0, type=socket.SOCK_STREAM)
    workspace.record("localhost_resolved", note="Resolution may come from the hosts file or cache; no DNS event is asserted")
    for index in range(file_count):
        workspace.file(f"{role}-example-{index:02d}.txt").write_text(
            "Harmless simulator scratch content. No existing user file is read or modified.\n", encoding="utf-8")
    workspace.record("scratch_files_created", count=file_count)
    server = LoopbackEcho()
    started = time.monotonic()
    exchanges = 0
    try:
        while time.monotonic() - started < duration:
            # Hold real TCP connections long enough to make polling visibility testable.
            with connect_loopback(server.address) as client:
                client.sendall(b"BIG-BROTHER-HARMLESS-TEST")
                if client.recv(128) != b"BIG-BROTHER-HARMLESS-TEST":
                    raise RuntimeError("Loopback echo failed")
                exchanges += 1
                workspace.record("loopback_exchange", role=role,
                                 parent_marker_present=workspace.file("parent-exiting.json").exists())
                time.sleep(min(.8, max(0, duration - (time.monotonic() - started))))
            time.sleep(.1)
    finally:
        server.close()
    workspace.record("work_completed", role=role, exchanges=exchanges)


def run_parent(workspace, scenario, duration=8, start_delay=2):
    workspace.record("parent_started", scenario=scenario)
    print(json.dumps({"harmless": True, "scenario": scenario, "run_directory": str(workspace.path),
                      "cleanup_token": workspace.token}), flush=True)
    time.sleep(start_delay)
    if scenario == "ordinary":
        bounded_work(workspace, duration, "ordinary", 3)
    elif scenario == "fanout":
        children = [spawn_child(workspace, f"helper-{i}", duration) for i in range(3)]
        try:
            bounded_work(workspace, duration, "fanout-parent", 12)
        finally:
            for child in children:
                child.wait(timeout=duration + 10)
                if child.returncode:
                    raise RuntimeError("A trusted simulator helper failed")
    elif scenario == "survivor":
        spawn_child(workspace, "surviving-helper", duration + 5)
        # Give the collector several polls with both parent and child alive.
        time.sleep(3)
        workspace.file("parent-exiting.json").write_text(json.dumps({"parent_pid": os.getpid()}), encoding="utf-8")
        workspace.record("parent_exit_requested", child_continues=True)
    else:
        raise ValueError("Unsupported simulator scenario")
    workspace.record("parent_completed", scenario=scenario)


def default_scenario():
    name = Path(sys.executable if getattr(sys, "frozen", False) else __file__).stem.lower()
    if "survivor" in name:
        return "survivor"
    if "fanout" in name:
        return "fanout"
    return "ordinary"


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scenario", choices=SCENARIOS, default=default_scenario())
    parser.add_argument("--scratch-root", type=Path)
    parser.add_argument("--duration", type=float, default=8)
    parser.add_argument("--start-delay", type=float, default=2)
    parser.add_argument("--child", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--run-dir", type=Path, help=argparse.SUPPRESS)
    parser.add_argument("--token", help="Ownership token required for cleanup")
    parser.add_argument("--role", default="helper", help=argparse.SUPPRESS)
    parser.add_argument("--clean-run", type=Path, help="Remove only a simulator-created token-marked run directory")
    args = parser.parse_args(argv)
    limit = 25 if args.child else 20
    if not 1 <= args.duration <= limit or not 0 <= args.start_delay <= 5:
        parser.error(f"Duration must be 1..{limit} seconds and start delay 0..5 seconds")
    if args.child and (not args.run_dir or not args.token or not re.fullmatch(r"[a-z0-9-]{1,32}", args.role)):
        parser.error("Child runs require an owned directory, token and bounded role")
    if args.clean_run and not args.token:
        parser.error("Cleanup requires the ownership token")
    return args


def main(argv=None):
    args = parse_args(argv)
    if args.clean_run:
        RunWorkspace(args.clean_run, args.token).clean()
        return 0
    if args.child:
        workspace = RunWorkspace(args.run_dir, args.token)
        try:
            bounded_work(workspace, args.duration, args.role, 8)
        except Exception as exc:
            workspace.record("child_failed", error=type(exc).__name__)
            raise
        return 0
    default_root = (Path(sys.executable).parent / "simulator-runs" if getattr(sys, "frozen", False)
                    else Path(__file__).resolve().parents[2] / ".cache" / "simulator-runs")
    workspace = RunWorkspace.create(args.scratch_root or default_root)
    run_parent(workspace, args.scenario, args.duration, args.start_delay)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
