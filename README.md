# Big Brother

Windows desktop process observation, behavioural anomaly scoring and evidence investigation. Select a process or executable, watch its descendants, inspect a chronological timeline and review findings linked to recorded events. An absence of findings does not establish safety.

![Big Brother investigation replay](artifacts/dashboard.png)

## Run on Windows

The per-user installer and portable executable are built into `release/`. Neither requires Python, Node, Docker, a paid API key or an external language model. See [Windows setup](docs/windows-setup.md) for package paths and optional richer telemetry.

Selecting a file does not execute it. **Launch and watch** is the explicit execution action. Watching an existing process labels earlier ancestry as incomplete. Closing the window hides the app in the tray; **Stop collection and exit** stops this app. Any separately installed Sysmon service remains active.

Use **Explore a replay → Investigation → Open replay** to inspect four processes, thirteen retained events and three findings. Replay data is fabricated, never executed and excluded from model evaluation. The active trained model scores its supported events; startup changes and surviving children are separately labelled transparent rules.

## Models actually trained

Trained a histogram-centroid feature baseline and a PyTorch temporal GRU on bounded real LANL 2015 process, DNS and network-flow telemetry prefixes. The GRU is selected by validation loss; its weights run through a checked standard-library export, without PyTorch in the app.

| Held-out test, 1,486 disjoint windows | Feature baseline | Temporal GRU |
|---|---:|---:|
| Next-event negative log likelihood, nats (lower is better) | 1.1192 | 0.6011 |
| Perplexity | 3.0624 | 1.8241 |
| Unlabelled windows above validation threshold | 29 / 1,486 | 24 / 1,486 |

These are predictive/anomaly results. The data used has no attack labels, so precision, recall, F1, PR-AUC, false-positive rate and malware-detection latency are unavailable. The model learns supported event sequences and port categories; file/Registry evidence and process ancestry are displayed but do not influence this model. Personal Windows applications can differ substantially from the reference enterprise telemetry. See [model card](docs/model-card.md), [dataset card](docs/dataset-card.md), [saved results](training/results/metrics.json) and [split definitions](training/results/splits.json).

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

Training dependencies are separate. Use `training/requirements.txt` and the CPU PyTorch index documented there. Download bounded source prefixes with `python training/acquire_lanl.py --prefix-mib 4`, then `python training/train.py --epochs 8 --seed 1984`. Keep the saved final test untouched while selecting architectures or thresholds. Training/export commands and scientific limitations are detailed in the model/dataset cards.

## Documentation

- [Architecture and trust boundaries](docs/architecture.md)
- [Windows setup and dependency changes](docs/windows-setup.md)
- [Telemetry capability matrix](docs/telemetry.md)
- [Local data, retention and privacy](docs/privacy.md)
- [Optional approved local/remote commentary](docs/optional-llm.md)
- [Dependency licences](THIRD_PARTY_NOTICES.md)
- [Final validation, package paths and exact commands](HANDOFF.md)

Monitoring and deterministic explanations are local. The optional LLM CLI requires review of a redacted preview and approval of its exact hash; remote requests additionally require explicit opt-in. It never determines detections or executes tools.

Packages are unsigned. Live Sysmon ingestion requires an existing configured readable channel; native polling and fabricated replay were validated on this Windows machine. Rich live Sysmon collection remains unverified here. No autonomous killing, blocking, quarantine or deletion of watched programs is implemented.
