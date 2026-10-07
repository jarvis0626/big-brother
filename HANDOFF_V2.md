# Big Brother 0.2.0 expanded research and Windows delivery

This iteration completed on the development Windows 11 machine on 7 October 2026. Times inside artifacts are UTC. Source history is backed up to the private [jarvis0626/big-brother repository](https://github.com/jarvis0626/big-brother). The previous `v0.1.0` tag, original model and [historical handoff](HANDOFF.md) remain available.

## Current application and packages

The application uses the real expanded GRU, local SQLite and documentation retrieval. Native Windows process/network polling works without additional services. It reads an already configured Sysmon channel when available; richer live Sysmon collection is unverified on this machine. It never installs that service or executes recorded attack commands.

The version 0.2.0 installer and portable launcher are delivered under `release/`. Both bundle the Windows runtime and require no Python, Node, paid API key or external language model. Packages are unsigned; exact bytes and SHA-256 are recorded in the checksum file below.

- Per-user installer: `release/Big-Brother-0.2.0-x64-nsis.exe`.
- Portable launcher: `release/Big-Brother-0.2.0-x64-portable.exe`, with retained `BigBrother-data` alongside it.
- Extracted application: `release/win-unpacked/Big Brother.exe`, with adjacent resources required.
- Harmless executable test programs: `release/simulators/`; source and safe run instructions are in [simulators-v2.md](docs/simulators-v2.md).
- Exact local package checksums: [PACKAGE_HASHES.txt](PACKAGE_HASHES.txt).

Selecting a file only selects it. **Launch and watch** explicitly starts the chosen executable. **Import recording** reads bounded normalized JSON as inert evidence, with a visible recorded label, provenance, capture gaps and retained history. Choosing a recording never launches its named programs. Closing the window hides it in the tray; use **Stop collection and exit** to stop the app.

## Actual training and evaluation

Three immutable 32 MiB LANL source prefixes contain 17,510,711 complete records. After excluding every v1 timestamp and separating host groups and time, v2 uses 90,235 training windows / 721,880 prediction targets, 11,908 validation windows and 8,048 fresh-test windows. Four GRUs and two feature baselines were fitted on CPU with two threads; total elapsed training was 1,060.69 seconds. Candidate and threshold decisions were frozen before the fresh test.

| Same fresh test | Expanded feature baseline | Unchanged v1 | Active v2 |
| --- | ---: | ---: | ---: |
| Next-event negative log likelihood, nats | 0.831453 | 0.603148 | 0.571488 |
| Perplexity | 2.296654 | 1.827863 | 1.770900 |
| Unlabelled windows above frozen threshold | 87 / 8,048 | 237 / 8,048 | 94 / 8,048 |

V2 improves prediction loss by 5.25% relative to unchanged v1 on identical new targets and 31.27% relative to the fairly trained baseline. Active version is `lanl2015-v2-gru-e16-h32-seed2026`, with 16-dimensional embedding, 32 hidden units, selected epoch 11 and validation threshold 7.014227390289307 nats. Weights SHA-256: `26adda072a62e5d6320686d04b7da98a2cbbdbe7c6a3559e37d8616bb025e95e`. Pure-Python output matches PyTorch within 6.71e-8 maximum probability error. Promotion checks result consistency, frozen artifact hashes, dimensions, schema and loading; the original model is preserved.

The model consumes ten categories of process start/end, DNS and network destination ports. It ignores file, Registry, process-access, module and remote-thread events. Its score is sequence surprise, not malware probability. Behavioral precision, recall, F1, false-positive rate, false alerts/hour and detection latency remain unavailable. The complete LANL annotation file has 749 red-team authentication records, all outside both experiments' observed intervals. Unannotated activity cannot be assumed benign.

The [model card](docs/model-card.md), [experiment report](docs/model-v2-experiments.md), [fresh metrics](training/results/v2/metrics.json), [selection freeze](training/results/v2/selection-freeze.json), [external check](training/results/v2/external-windows.json) and [promotion record](training/results/v2/promotion.json) preserve the measured results and limits.

## Acquired data and scenario checks

The [catalog](training/catalog-v2.json) researches sixteen relevant source families with licenses, sensor compatibility and acquisition exclusions. Actual pinned OTRF and EVTX corpora supply 264 unique lab recordings and 986,382 normalized Windows events. Raw inputs and normalized captures stay on D: under `training/data/`, ignored by Git and excluded from installers. Source hashes, revisions, excluded records and coverage are tracked in [corpus-v2-manifest.json](training/corpus-v2-manifest.json).

External evaluation never fits these recordings: only 19,867 events (2.014%) match behavioral vocabulary; 57 recordings yield 725 complete windows / 5,800 targets. V1 loss 2.305962 becomes v2 loss 1.274351. This is prediction transfer, not attack-detection accuracy. Approximately 98% of their richer evidence remains outside this model. Attack scenario names contain background activity and do not label each event or process.

Imported evidence can trigger separately labelled reference rules for startup changes, surviving-child connections, memory-capable LSASS access and remote-thread creation. These cite recorded facts and versioned documentation; query-only access does not match the memory rule. They retain null model scores and acknowledge legitimate explanations. Recorded real LSASS and remote-thread captures were checked in the GUI without running their commands.

The production import validator accepts 244 of the 264 full normalized recordings, containing 104,850 events. Twenty larger recordings exceed declared bounds: ten event-count caps, seven 32 MiB input caps and three 8 MiB normalized evidence budgets. There are no remaining structural or known-PID inconsistencies in this corpus scan. Larger sources remain available for offline research. Recording analysis/state includes all retained events up to the 10,000-event limit; live sessions display/score the latest 2,000 events. Unknown event PIDs remain explicitly unknown. See [validator scan](artifacts/recording-validation-v2.json).

Two real regression captures were verified after fixes: 3,260 events with five missing PIDs, and 3,660 events with an early remote-thread event previously outside the latest-2,000 slice. Both now preserve original evidence, findings and visible citations. Their full UI renders took 2.01/3.45 seconds, with citation navigation 214/271 ms. These isolated checks do not benchmark the 10,000-event limit. See [recording reproduction](artifacts/recording-reproduction-v2.json).

The separate [EMBER experiment](docs/static-pe-experiment.md) uses a verified 1,696,539,273-byte feature-only archive and an independent 564-feature projection. Preparation read 1,000,000 records in 678.02 seconds; after identity, label, time and duplicate exclusions, retained samples are 112,391 training / 37,535 validation / 49,742 chronological test. The linear baseline and LightGBM actually fitted/evaluated in 68.14 seconds; validation average precision selected LightGBM. Its heldout ROC AUC is 0.976334 and average precision 0.977838, versus baseline 0.864080 / 0.837895.

| LightGBM operating point chosen on validation | Heldout precision | Heldout recall | Heldout F1 | Heldout false-positive rate |
| --- | ---: | ---: | ---: | ---: |
| Best validation F1, threshold 0.354045 | 88.55% | 95.03% | 0.916772 | 12.33% |
| Validation benign-score 99th percentile, threshold 0.836476 | 98.31% | 73.44% | 0.840732 | 1.265% |

The high false-positive rate at the F1 threshold illustrates the operating-point and time-shift limitation; the lower-FPR setting misses more publisher-labeled malware. These are historical benchmark rates with their own prevalence, not this app's detection performance or current installed-software accuracy. No threshold was adjusted after observing test. The experiment does not download malware binaries or provide runtime executable classification. Extraction parity with current Windows executables remains unverified. Weights, source provenance and measured outcomes are in [static-v2 results](training/results/static-v2/metrics.json).

An independent bounded native archive audit found 200,000 raw test records and 200,000 unique file SHA identities, with zero repeats or conflicting known labels. One oversized row's identity was recovered but its class label remains unknown. The test-member hash matches preparation. Saved LightGBM and linear weights reproduced 512 recorded scores exactly, with no decision differences at either frozen threshold. See [identity audit](training/results/static-v2/identity-audit.json) and [artifact validation](training/results/static-v2/artifact-validation.json).

## Verification and measured limits

The final combined Python suite passed 129 checks in 18.08 seconds, including live Windows attribution, real-corpus regressions, rollback/retention, parser bounds, checked promotion and static-experiment freeze/path guards. All eight desktop boundary tests passed. The source GUI passed 15 checks, including native recording import, factual citations, export, collector isolation, tray behavior and retained history. Separate real recorded imports checked exact LSASS/thread citation navigation and larger captures without execution.

The actual packaged Electron GUI passed all 15 checks with the active expanded model. After refreshing final documentation, both delivered launchers were verified again: the installer installed, launched and uninstalled successfully; the portable outer launcher started with adjacent retained data. Both launched with Python and Node absent from PATH, correct 0.2.0 metadata, sandboxed renderer, no renderer Node access, bundled resources and the model available. See [installer checks](artifacts/installer-smoke.json), [portable checks](artifacts/portable-smoke.json), [packaged GUI](artifacts/packaged-gui-smoke.json) and final hashes in [PACKAGE_HASHES.txt](PACKAGE_HASHES.txt).

Two additional fresh Git checkout checks passed with Windows line-ending conversion enabled and disabled. The v0.2 `.gitattributes` preserves exact model, dataset-manifest and frozen research-result bytes; stage verification confirmed their recorded hashes are unchanged. This makes the source snapshot reproducible across Git line-ending settings without modifying any learned values.

Fresh production simulator validation used the promoted model and unchanged threshold:

| Known harmless workload | Actual events | Maximum anomaly score | Reference findings |
| --- | ---: | ---: | --- |
| Ordinary temporary files and loopback | 18 | 6.3413 | None |
| Trusted child fan-out | 68 | 1.4480 | None |
| Child continuing after parent exit | 30 | 2.2985 | One cited surviving-child reference |

All runtime processes were attributed, network activity stayed on loopback, owned scratch files were cleaned and no events were dropped in these runs. File creation was generated but not collected by native polling because Sysmon is unavailable. Three known harmless workloads are engineering checks, not a representative benign benchmark or malware accuracy estimate. See [simulator results](artifacts/simulator-validation-v2.json), [source GUI](artifacts/gui-smoke.json) and [recorded thread GUI](artifacts/recording-rules-ui-v2.json).

Measured short backend workloads on Ryzen 7 5800H, 16 logical CPUs and 31.38 GiB usable RAM: mean one-core CPU 0.31% idle, 2.63% ordinary live watch and 13.95% repeated fabricated replay; mean RSS 30.99–32.66 MiB. CPU 100% means one logical core. This excludes Electron and separately installed Sysmon overhead. The larger network raises repeated-replay cost relative to v1. Full durations and peaks are in [performance.json](artifacts/performance.json).

## Reproduction

Use the existing D: virtual environment for runtime/build checks, and the research Python with the pinned [training requirements](training/requirements.txt) plus [static requirements](training/static-requirements.txt) for fitting. All new downloads, temporary directories, numeric matrices and build caches use D:, with a 20% free-space reserve. No CUDA GPU is present; actual training used CPU.

```powershell
# Runtime and Windows checks
.venv\Scripts\python.exe -m pytest tests -q
npm.cmd run test:desktop
npm.cmd run test:gui
.venv\Scripts\python.exe -m backend.service --self-test --resources resources
.venv\Scripts\python.exe scripts/validate_simulators.py
.venv\Scripts\python.exe scripts/benchmark.py

# Independently reproduce v2 without replacing frozen results
C:\Python312\python.exe training/expand_lanl.py --prefix-mib 32
C:\Python312\python.exe training/train_v2.py --epochs 16 --patience 3 --max-train-windows 100000 --max-eval-windows 15000 --threads 2 --output-dir training/results/reproduced-v2 --cache-dir training/cache/reproduced-v2 --v1-models-dir training/results/v2/v1-original
C:\Python312\python.exe training/audit_v2.py
C:\Python312\python.exe training/evaluate_external_v2.py

# Public recording and static-feature research acquisition
.venv\Scripts\python.exe training/datasets_v2.py --acquire --normalize
C:\Python312\python.exe training/validate_static_pe_v2.py
# For a separate numerical reproduction, use the fresh data/results paths in
# docs/static-pe-experiment.md; the original observed experiment is frozen.

# Windows build and actual package workflows
powershell -ExecutionPolicy Bypass -File scripts/build.ps1
powershell -ExecutionPolicy Bypass -File scripts/package-smoke.ps1 -Target installer
powershell -ExecutionPolicy Bypass -File scripts/package-smoke.ps1 -Target portable
$env:BB_SMOKE_EXE = Join-Path (Get-Location) 'release\win-unpacked\Big Brother.exe'
npm.cmd run test:gui
Remove-Item Env:\BB_SMOKE_EXE
```

Acquisition counts can differ on another machine; preserve visible exclusions and compare hashes. The audit/external commands inspect the saved frozen v2 experiment. Reproduce historical v1 in a separate `v0.1.0` checkout because its trainer writes runtime weights. Do not reuse observed final-test results for a new tuning search.

Private milestone history contains the corpus/import/simulator checkpoint `a784f516eaeb0bfcf4cac6428cb04927eb77d6bd` and tested model/rule checkpoint `e40bd7b325e49795b13104479e577afe7842170b`. Remote SHAs and private visibility were checked after pushing. Major changes continue to be recorded without committing raw telemetry, caches, credentials or generated packages. Significant work and real command/test outcomes were reported through Codewatch.
