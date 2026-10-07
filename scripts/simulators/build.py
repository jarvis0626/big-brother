"""Build three launchable, identical harmless executable variants on D:."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
NAMES = {
    "ordinary": "BigBrotherOrdinarySimulator.exe",
    "fanout": "BigBrotherFanoutSimulator.exe",
    "survivor": "BigBrotherSurvivorSimulator.exe",
}


def main():
    if os.name != "nt":
        raise SystemExit("Build these Windows executables on Windows")
    build = ROOT / "build" / "simulators"
    release = ROOT / "release" / "simulators"
    cache = ROOT / ".cache" / "simulator-build"
    for path in (build, release, cache):
        path.mkdir(parents=True, exist_ok=True)
    env = {**os.environ, "TEMP": str(cache), "TMP": str(cache), "PYINSTALLER_CONFIG_DIR": str(cache / "pyinstaller")}
    command = [sys.executable, "-m", "PyInstaller", "--noconfirm", "--clean", "--onefile", "--console",
               "--name", "BigBrotherOrdinarySimulator", "--distpath", str(release),
               "--workpath", str(build / "work"), "--specpath", str(build),
               "--runtime-tmpdir", str(cache / "runtime"), str(Path(__file__).parent / "behavior_app.py")]
    subprocess.run(command, cwd=ROOT, env=env, check=True)
    ordinary = release / NAMES["ordinary"]
    for scenario, name in NAMES.items():
        if scenario != "ordinary":
            shutil.copy2(ordinary, release / name)
    report = {"purpose": "Harmless bounded collector tests; these are not malware", "binaries": [
        {"scenario": scenario, "filename": name, "bytes": (release / name).stat().st_size,
         "sha256": hashlib.sha256((release / name).read_bytes()).hexdigest()}
        for scenario, name in NAMES.items()]}
    (release / "build-manifest.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
