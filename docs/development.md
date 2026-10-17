# Development and research

This document preserves the engineering and research detail behind the v1.1.0 desktop release. The app uses the same frozen behavioral v2 model and comparison threshold; the changes concern observation semantics and presentation. Historical [v1.0.0 notes](releases/v1.0.0.md) remain preserved.

## Current reference-scoring behavior

Model comparisons appear as neutral **Behavior notes**, outside the **Findings** count. Findings remain the separately labeled evidence-rule results. Explanations cite observed event categories and identify the older enterprise reference domain; neither the model nor the rules establish server reputation or malware probability.

Existing sessions refresh their stored analysis once on first view using the same recorded evidence and current classification rules. This initial compatibility refresh also applies to paused sessions; further reviews respect paused analysis.

Reference scoring waits for sixteen preceding supported events plus a target event. Short sequences expose a waiting status and no score. For polling TCP snapshots, only `ESTABLISHED` records become model inputs; `SYN_SENT`, closing and unknown-state TCP snapshots remain raw evidence in the timeline, reports and rule evaluation. This change does not filter genuine Sysmon network events or UDP snapshots on the basis of TCP state.

The model version remains `lanl2015-v2-gru-e16-h32-seed2026`, with weight SHA-256 `26adda072a62e5d6320686d04b7da98a2cbbdbe7c6a3559e37d8616bb025e95e` and threshold `7.014227390289307`. No new fitting or threshold calibration was performed for v1.1.0. The **Online connections** replay is fabricated workflow/regression data, not independent benign or malicious ground truth. The [new benign-source audit](benign-data-audit.md) records why SILRAD was acquired for inspection and excluded from deployment training.

## Local diagnostic holdouts

`scripts/local_behavior_dataset.py` reads one explicitly selected live session through SQLite's read-only mode. It does not search for databases, select sessions automatically, fit a model, calibrate a threshold or upload data. From this D: checkout, supply both the database's absolute path and the selected session's ID, available as `session.id` in that session's local JSON report:

```powershell
.venv\Scripts\python.exe scripts/local_behavior_dataset.py --database "D:\Private\BigBrother-data\big-brother.sqlite3" --session "session_ID_from_your_report"
```

The example path and ID are placeholders. The helper prints aggregate counts only. Its privacy-reduced file goes into ignored `training/data/v3/local`: event order and categories, capture-local process relationships, coarse port groups, source/snapshot flags and TCP state. It omits original paths, command lines, addresses, raw process IDs, session IDs and timestamps. Coarse sequences can still be identifying, so keep the file local and review any future sharing separately.

Every file is fixed to role `diagnostic_holdout` and label `user_reported_expected`, with fitting, calibration and automatic upload disabled. A user's report of expected behavior is not independently verified benign ground truth. This format is separate from imported app recordings and is not a model-training input. A reported problem can become a regression case, but it cannot also serve as an unseen test of improvements tuned to it. See [the collector-matched data plan](benign-data-audit.md).

## Models actually trained

Version 0.2.0 activates a larger temporal GRU selected from four neural runs and two histogram baselines. Expanded LANL 2015 prefixes contain 17,510,711 complete process/DNS/network records. After excluding all v1 timestamps and separating hosts/times, training uses 90,235 windows and 721,880 next-event targets, about nine times v1. A checked standard-library export runs the actual weights without PyTorch in the app.

| Same fresh test, 8,048 disjoint windows | Expanded baseline | Unchanged v1 | Active v2 |
|---|---:|---:|---:|
| Next-event loss, nats (lower is better) | 0.831453 | 0.603148 | 0.571488 |
| Perplexity | 2.296654 | 1.827863 | 1.770900 |
| Unlabelled windows above frozen threshold | 87 / 8,048 | 237 / 8,048 | 94 / 8,048 |

V2 reduces prediction loss by 5.25% relative to v1 on the same new holdout. These are predictive/anomaly results. Malware precision, recall, F1, false-positive rate and detection latency remain unmeasured. The model consumes process start/end, DNS and port categories; file, Registry, process-access, module and remote-thread evidence stays outside its inputs. See [model card](model-card.md), [expanded experiment](model-v2-experiments.md) and [saved results](../training/results/v2/metrics.json). Historical v1 results and the `v0.1.0` tag are preserved.

## Recorded scenarios and harmless test applications

The [dataset catalog](../training/catalog-v2.json) reviews sixteen relevant families. Actual pinned OTRF and EVTX lab logs supply 264 unique recordings and 986,382 normalized Windows events. They are held out from fitting. External prediction improves, but only 2.014% of their events fit this model's vocabulary. Scenario attack labels include mixed background activity and are not event-level malware ground truth.

**Import recording** reads bounded normalized JSON through a native file dialog, displays recorded coverage/provenance and never executes dataset commands. Separately labelled reference rules cite actual startup changes, surviving children, memory-capable access to `lsass.exe` and remote-thread events. The latter two follow [Microsoft access-rights documentation](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights) and [Sysmon event documentation](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon); legitimate tools can generate them.

Three [harmless simulator executables](simulators-v2.md) exercise files in owned scratch folders, trusted child processes and loopback traffic. Live v2 tests produced no anomaly findings for these benign workloads, while the surviving-child reference retained valid citations. They test attribution and workflow, not malware accuracy. A separate [EMBER static-feature study](static-pe-experiment.md) trains supervised research models from numeric features without downloading malware binaries; extractor parity is not established, so it is not a shipped executable scanner.

The completed static study retained 112,391 training samples and 49,742 chronological test samples. LightGBM's heldout ROC AUC is 0.976334, with both frozen threshold tradeoffs documented. Its saved weights reproduced recorded scores exactly. Static benchmark performance remains separate from the deployed behavioral model.

Official OpTC downloads were quota-blocked. An inspected transformed OpTC mirror was excluded from training because its conversion provenance was undocumented. LANL prefixes came from a public mirror whose publisher documents official-source acquisition; full-file equality to the registration-gated official originals was not independently verified. Dataset revision, prefix checksums and exclusions are recorded in the manifest.

## Development and reproducibility

From this repository in PowerShell:

```powershell
python -m venv .venv
.venv\Scripts\python.exe -m pip install -r requirements.txt --cache-dir .cache/pip
npm.cmd ci
npm.cmd run build:ui
npm.cmd start
```

For Vite development use `npm.cmd run dev`. `npm.cmd` avoids changing PowerShell's script-execution policy.

```powershell
# Build both Windows packages, with all caches/temp files on D:
powershell -ExecutionPolicy Bypass -File scripts/build.ps1

# Meaningful Windows and model checks
.venv\Scripts\python.exe -m pytest tests -q
npm.cmd run test:desktop
npm.cmd run test:gui
.venv\Scripts\python.exe -m backend.service --self-test --resources resources
.venv\Scripts\python.exe scripts/benchmark.py
```

Training dependencies are separate. Use `training/requirements.txt` and the CPU PyTorch index documented there. Follow [v2 reproduction](model-v2-experiments.md) for a separate output directory; the trainer refuses to overwrite frozen results. The original `training/train.py` is historical and writes runtime weights, so reproduce v1 in a checkout of `v0.1.0`. Do not retune after observing final-test results.

## Documentation

- [Architecture and trust boundaries](architecture.md)
- [Windows setup and dependency changes](windows-setup.md)
- [Telemetry capability matrix](telemetry.md)
- [Local data, retention and privacy](privacy.md)
- [Optional approved local/remote commentary](optional-llm.md)
- [Dependency licences](../THIRD_PARTY_NOTICES.md)
- [Ordinary and investigation replay demo](demo.md)
- [Private GitHub checkpoints and rollback](version-history.md)
- [Expanded validation, package paths and exact commands](../HANDOFF_V2.md)
- [Historical v0.1.0 handoff](../HANDOFF.md)

Monitoring and deterministic explanations are local. The optional LLM CLI requires review of a redacted preview and approval of its exact hash; remote requests additionally require explicit opt-in. It never determines detections or executes tools.

Packages are unsigned. Live Sysmon ingestion requires an existing configured readable channel; native polling and fabricated replay were validated on this Windows machine. Rich live Sysmon collection remains unverified here. No autonomous killing, blocking, quarantine or deletion of watched programs is implemented.
