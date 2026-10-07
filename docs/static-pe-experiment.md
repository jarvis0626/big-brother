# Separate static PE classification experiment

This research experiment trains supervised models from published [EMBER 2018 feature-only data](https://github.com/elastic/ember). It does not change the Windows behavioral model, execute malware, download binary samples or provide a shipped executable scanner. Static benchmark classification and anomaly scoring over observed process events are separate tasks.

The official archive is `ember_dataset_2018_2.tar.bz2`, 1,696,539,273 bytes, with publisher SHA-256 `b6052eb8d350a49a8d5a5396fbe7d16cf42848b86ff969b77464434cf2997812`. The publisher's [license at the inspected immutable revision](https://github.com/elastic/ember/blob/d97a0b523de02f3fe5ea6089d080abacab6ee931/LICENSE.txt) assigns **MIT** to the referenced data and **AGPL-v3** to its code. Big Brother's projection is independently written from the public raw schema; the publisher's extraction code is neither executed nor bundled.

Inputs remain under `training/data/v2/static-ember` on D:. The compressed archive is verified in full, then streamed without extracting raw JSON to disk. Cached matrices contain only a deterministic quarter of eligible file SHA identities. Labels, appearance month, hashes, malware family and source file name are excluded from the 564 input features. Inputs contain log-scaled general/header/string counts, normalized byte and byte-entropy histograms, data-directory sizes and section summaries. This is a smaller independent projection, not the publisher's full feature-vector benchmark.

Before held-out results are calculated, the experiment fixes the following protocol:

1. Use published class labels 0/1; exclude unlabeled `-1` entries.
2. Select SHA-256 identities whose first eight hexadecimal digits modulo four equal zero, independent of labels.
3. Fit only official training samples first seen through August 2018; use September–October 2018 official training samples for validation. Reserve November 2018 onward official test samples for final evaluation.
4. Remove repeated original file hashes. Exclude all raw training file identities from held-out data regardless of the subset. Remove exact projected-feature duplicates within each split and across fitting/validation/test.
5. Fit a scaled linear logistic-loss baseline and LightGBM with fixed seed 1984 and two CPU threads. LightGBM early stopping uses validation average precision. Choose the model by validation average precision and thresholds by validation F1 and a separate validation benign-score 99th percentile.
6. Write `training/results/static-v2/frozen-plan.json` before held-out prediction. Score the held-out set once and report ROC AUC, average precision, confusion counts, precision, recall, F1, false-positive rate, log loss and Brier score at the frozen thresholds.

Month resolution is coarse. Family-disjoint generalization is not established: reliable complete families are absent for benign files, and malware families can overlap over time. Exact identity/vector checks do not eliminate every near duplicate, signer, packer or collection bias. Publisher labels are historical judgments, not new independent malware adjudications. Rates reflect the selected benchmark's prevalence and cannot become live false-alerts-per-hour estimates.

The official extractor used LIEF 0.9.0 for version-two features and documents compatible extraction with LIEF 0.10.1. Those are older APIs; parity with modern Windows/Python and current executable formats has not been validated. Classification from publisher raw features is therefore research-only until an independently reviewed extractor reproduces the selected features on representative harmless executables and malformed PE cases. No claim about current installed applications follows from a high historical benchmark score.

Run with the existing research Python environment containing NumPy, scikit-learn and LightGBM:

```powershell
C:\Python312\python.exe training\static_pe_v2.py --acquire --prepare --train
```

`--prepare` verifies the complete archive before reading it. `--train` verifies cached matrix hashes from the dataset manifest. Research weights, frozen decisions and numerical results go to `training/results/static-v2`; large data matrices stay ignored in the D: cache. Actual metrics and measured sample counts are recorded in that directory's JSON files after execution, and this document is updated from those observed results.
