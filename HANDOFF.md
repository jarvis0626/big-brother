# Big Brother 0.1.0 delivery — 7 October 2026

Built and tested Windows x64 installer and portable packages. Core observation, replay, scoring and evidence explanations run locally with the bundled Python runtime and trained model. End users do not install Python, Node, PyTorch or a language model.

## Packages and launch

From `D:\Projects\Big Brother`:

```powershell
# Interactive per-user installation; then use the Big Brother shortcut
& '.\release\Big-Brother-0.1.0-x64-nsis.exe'

# Portable: keep in a writable folder; data is saved beside the executable
& '.\release\Big-Brother-0.1.0-x64-portable.exe'

# Development desktop, using the existing project dependencies
npm.cmd start
```

Both packages are **unsigned**, verified using Windows Authenticode inspection. Exact delivered sizes and SHA256 hashes are in [PACKAGE_HASHES.txt](PACKAGE_HASHES.txt). Generated executables remain local in `release/`; they are excluded from source control. Installed data uses Electron's current-user application data directory; portable data uses adjacent `BigBrother-data`.

## Implemented workflow

The sandboxed Electron/React interface opens into the dashboard. Users can select an executable without running it, explicitly launch and watch it, or choose an existing process. Native Windows polling follows recorded identities and descendants, including surviving children. Existing-process ancestry and collector blind spots are labelled. Optional Sysmon ingestion reads an already configured Windows Event Log channel; it never installs or modifies a privileged service.

SQLite retains sessions, processes, timestamped evidence, provenance, stable relationships and findings. The app handles duplicate/out-of-order events, PID reuse, bounded queues, retention, dropped-event gaps and collector restarts. Users can inspect the graph and searchable timeline, open event citations from a finding, change resource limits, delete sessions, export reports, pause/resume sessions, close to tray and reopen retained history.

Actual trained-model findings and transparent startup/surviving-child reference rules are labelled separately. Deterministic explanations retrieve observed subgraphs and a versioned Microsoft/MITRE knowledge corpus. They separate observations, possible interpretations, missing information and suggested checks, with event IDs and documentation sources. No external LLM is required. An optional approved-provider CLI supports redacted previews, exact-hash approval, explicit remote opt-in and Windows Credential Manager; it is separate from the desktop collector and requires a running provider.

The [short demo](docs/demo.md) exercises ordinary and suspicious-looking **fabricated** records, without executing their command lines or creating persistence. The investigation replay produces four processes, thirteen retained events and three findings: one trained-model finding and two transparent rules. The ordinary replay produces one process, three events and no findings. Neither replay is accuracy evaluation data.

## Actual data and training

Official OpTC and LANL documentation, schemas, sizes and redistribution terms were investigated before acquisition. Fresh official OpTC archive requests encountered quota errors. Three complete transformed OpTC mirror files were inspected and checksummed but excluded because transformation provenance was undocumented.

The trained experiment uses real LANL 2015 process, network-flow and DNS telemetry from the public Taqui mirror, pinned to revision `d7a15d0d504051bfe6cbc3f65377830704e824cc`. Acquired four MiB compressed prefixes per stream: twelve MiB compressed, 2,209,608 complete decoded rows, approximately 63 MB decoded. A partial final record is excluded. Prefix hashes cannot verify full archive footers or independently establish equality with registration-gated official originals. The publisher's documented acquisition claim and official public-domain/CC0-style waiver are recorded in the [dataset card](docs/dataset-card.md).

The common usable interval is seconds 1–17,910. Host hash buckets and time are both disjoint: training buckets 0–5 before 10,746; validation buckets 6–7 from 10,746 to 14,328; test buckets 8–9 thereafter. Selected 10,000 training, 979 validation and 1,486 final-test non-overlapping 24-event windows. Each uses 16 context events and eight targets. Preprocessing fits training only; validation chooses the default/epoch and thresholds before final test.

Trained an eight-centroid histogram feature baseline and an eight-dimensional embedding / sixteen-unit temporal GRU for eight epochs, seed 1984, CPU with two threads. The active model is `lanl2015-v1-seed1984`. Training/preparation took 30.55 seconds; final sampled training RSS was 537 MiB, with peak training memory unmeasured. Checked JSON export agrees with PyTorch within a maximum category-probability difference of 2.8222e-7 across 32 validation contexts. The packaged scorer uses standard-library arithmetic and verifies artifact hash/schema compatibility; missing models are visibly unavailable.

| Held-out measure | Feature baseline | Temporal GRU |
|---|---:|---:|
| Validation next-event loss, nats | 0.862721 | 0.595777 |
| Test next-event loss, nats | 1.119207 | 0.601077 |
| Test perplexity | 3.062425 | 1.824083 |
| Fixed validation anomaly threshold, nats | 5.712149 | 6.423330 |
| Unlabelled test windows above threshold | 29 / 1,486 | 24 / 1,486 |

There are 11,888 held-out target predictions. These results establish improved next-event prediction on this subset, not malware-detection accuracy. No attack labels were acquired: precision, recall, F1, PR-AUC, false-positive rate, false alerts/hour and detection latency are unavailable. Rare network-DNS targets performed worse with the GRU; subgroup results are saved. Scores are surprise in nats, never malware probabilities. File/Registry events and process ancestry are displayed evidence but are excluded from this model. The original graph-based malware research question remains unanswered by this acquisition.

The [tracked acquisition manifest](training/dataset-manifest.json), [model card](docs/model-card.md), [metrics](training/results/metrics.json), [splits](training/results/splits.json), checkpoints and export preserve the experiment. Training checks the actual cached prefix/text hashes and immutable provenance before fitting. Raw source downloads remain under ignored `training/data/` on D:.

## Verification actually performed on Windows

- Final Python suite: **45 passed in 16.10 seconds**, covering identities, relationships, deduplication, ordering, surviving children, harmless native telemetry, retention/deletion, evidence citations, untrusted text, model loading/parity/splits, provenance, optional-provider approval and private GitHub guards.
- Desktop security suite: **3 passed**, validating renderer method/parameter and external-link boundaries.
- Actual source and packaged Electron GUI: **13 checks passed each**, including model finding, citation navigation, export through a native save dialog, settings, process picker, pause/resume/stop, tray/reopen, ordinary replay and persisted history. No uncaught renderer errors. See [packaged GUI evidence](artifacts/packaged-gui-smoke.json) and [screenshot](artifacts/dashboard.png).
- Frozen standalone service self-test passed with actual bundled model and replay.
- Actual per-user installer installed into a new test directory, launched the packaged app with Python/Node removed from PATH, loaded the trained model, then uninstalled successfully and removed the app. Actual portable outer launcher passed the same runtime checks and stored data beside itself. Both verified sandboxing, denied renderer Node, bundled resources and three replay findings. See [installer](artifacts/installer-smoke.json) and [portable](artifacts/portable-smoke.json) evidence. This was this development Windows machine, not a separate fresh computer.
- Harmless workload used trusted children, temporary files and loopback HTTP. No malware, real startup persistence or Defender changes were used.

Short backend overhead measurements on Windows 11 build 26200, Ryzen 7 5800H, sixteen logical CPUs, 31.38 GiB usable RAM:

| Workload | Duration | Mean CPU, one-core denominator | Mean RSS |
|---|---:|---:|---:|
| Idle, no selected session | 5.21 s | 0.31% | 35.09 MiB |
| Benign selected process, files/child/loopback HTTP | 7.04 s | 3.30% | 36.14 MiB |
| Repeated thirteen-event replay, twelve sessions | 5.40 s | 5.18% | 36.43 MiB |

This measures the backend plus Windows Python launcher children; it excludes Electron and Sysmon service overhead and is not a broad personal-computer benchmark. Full data is in [performance.json](artifacts/performance.json). Single exported prediction latency was median 2.740 ms / p95 2.970 ms; a complete eight-prediction score call was median 30.960 ms / p95 37.512 ms. Timing fixtures do not support detection-accuracy claims.

## Reproduce

Build both packages with runtime dependencies and caches/temp on the project drive:

```powershell
Set-Location -LiteralPath 'D:\Projects\Big Brother'
powershell -ExecutionPolicy Bypass -File scripts/build.ps1
# Existing dependencies: add -SkipInstall
```

`Bypass` applies to that child PowerShell process only; no global execution-policy change is required. Training is separate from the runtime environment:

```powershell
$env:PIP_CACHE_DIR = Join-Path (Get-Location) '.cache\pip'
$env:TEMP = Join-Path (Get-Location) '.cache\temp'
$env:TMP = $env:TEMP
New-Item -ItemType Directory -Path $env:TEMP -Force | Out-Null
python -m venv .venv-training
.\.venv-training\Scripts\python.exe -m pip install torch==2.10.0 --index-url https://download.pytorch.org/whl/cpu
.\.venv-training\Scripts\python.exe -m pip install -r training/requirements.txt
.\.venv-training\Scripts\python.exe training/acquire_lanl.py --prefix-mib 4 --revision d7a15d0d504051bfe6cbc3f65377830704e824cc
.\.venv-training\Scripts\python.exe training/train.py --epochs 8 --seed 1984
```

Verification commands:

```powershell
.\.venv\Scripts\python.exe -m pytest tests -q
npm.cmd run test:desktop
npm.cmd run test:gui
$env:BB_SMOKE_EXE = Join-Path (Get-Location) 'release\win-unpacked\Big Brother.exe'
npm.cmd run test:gui
Remove-Item Env:\BB_SMOKE_EXE
powershell -ExecutionPolicy Bypass -File scripts/package-smoke.ps1 -Target installer
powershell -ExecutionPolicy Bypass -File scripts/package-smoke.ps1 -Target portable
.\.venv\Scripts\python.exe -m backend.service --resources resources --self-test
.\.venv\Scripts\python.exe scripts/benchmark.py
```

## Limits and version history

Rich live Sysmon collection remains **unverified here**, because no configured channel was available. Native Windows polling and replay were tested; polling can miss brief processes/connections and cannot supply file/Registry/DNS events. The app discloses these gaps. Sysmon requires separate explicit privileged setup and applicable licence acceptance; see [Windows setup](docs/windows-setup.md) and [capability matrix](docs/telemetry.md). Other Windows versions, ARM, production SmartScreen reputation and separate-machine installation remain unverified.

No full-file reads, encrypted traffic contents, antivirus verdicts or autonomous remediation are provided. Sensitive histories stay local by default with retention/deletion controls. The database is not application-encrypted. See [privacy](docs/privacy.md), [architecture](docs/architecture.md) and [dependency notices](THIRD_PARTY_NOTICES.md).

Source milestones are pushed to the private [jarvis0626/big-brother repository](https://github.com/jarvis0626/big-brother). The first source checkpoint is `8651940`; the completed release checkpoint is identified by tag `v0.1.0`. Major tested future changes use the private-verifying checkpoint helper documented in [version history](docs/version-history.md). No force push or public publishing is part of that workflow.
