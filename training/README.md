Training uses actual public-domain LANL2015 process, network-flow and DNS telemetry. These are bounded raw archive prefixes from the public Taqui mirror, whose publisher documents official-source acquisition. Source equivalence is a publisher claim; the official LANL documentation verifies schema and licence. Partial archive hashes verify our acquired prefix only.

From the repository directory in PowerShell, with Python 3.12 and the training requirements installed:

```powershell
python training/acquire_lanl.py --prefix-mib 4
python training/train.py --epochs 8 --seed 1984
.venv/Scripts/python.exe -m pytest tests/test_model.py -q
```

The downloader caps each compressed source at 4 MiB, enforces a 20% disk reserve and128MiB expansion bound per source, resumes byte ranges, excludes partial final records, and records SHA256. It never executes dataset contents. It writes training/data/lanl-manifest.json and saves source documentation. No raw dataset is included in installers.

Common available time is the intersection of all three prefixes. Training uses the first 60% of that period on host hash buckets 0..5; validation uses the next 20% on buckets 6..7; final test uses the last 20% on buckets 8..9. Related24-event windows are disjoint and grouped by host; exact duplicate raw rows are excluded. Histogram centroids and next-event distributions fit training only. Epoch, default model and99th-percentile maximum-surprise threshold use validation only. Test is evaluated once after these decisions.

The baseline learns 8 centroids of 16-event token histograms and smoothed next-token distributions. The temporal model is an 8-dimensional embedding plus 16-unit PyTorch GRU. Both predict the same targets using the same 16 events and fixed 10-token vocabulary. Each window comprises 16 context events and 8 targets, with a fresh 16-event rolling context for each target. The highest target negative log likelihood is the anomaly score. Token probabilities predict event categories; they are never probabilities of maliciousness.

The active model is selected by validation prediction loss. Both JSON artifacts and active.json are saved under resources/models. Packaged inference uses standard-library arithmetic and a tested JSON export. training/results preserves metrics, split definitions, window identities and a PyTorch checkpoint; the checkpoint is a local training output and is never loaded by the application.

No red-team labels were acquired. Precision, recall, F1, PR-AUC, false-positive rate, false alerts/hour and detection latency are unavailable. Threshold-exceedance fractions use unlabelled held-out windows and cannot be called false-positive rates. Recorded replay fixtures are never training or evaluation data.

The optional acquire.py retains bounded official OpTC-prefix acquisition, which encountered public Google Drive quota pages on 2026-10-07. acquire_mirror.py acquired three small complete OpTC-derived Parquet host files and verified their publisher hashes. These transformed files have no conversion documentation and are excluded from every training result. Running that optional inspection requires pyarrow; it is unnecessary for the shipped model.
