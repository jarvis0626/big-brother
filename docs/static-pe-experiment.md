# Separate static PE classification experiment

This research experiment trains supervised models from published [EMBER 2018 feature-only data](https://github.com/elastic/ember). It does not change the Windows behavioral model, execute malware, download binary samples or provide a shipped executable scanner. Static benchmark classification and anomaly scoring over observed process events are separate tasks.

The completed run read **1,000,000 raw feature records**, retained **112,391 fitting / 37,535 validation / 49,742 held-out samples**, and selected LightGBM by validation average precision. On the November/December 2018 held-out subset, LightGBM achieved ROC AUC **0.97633** and average precision **0.97784**. These are historical static-feature benchmark results; current installed applications have no verified matching feature extractor.

Both operating points were selected on validation and frozen before any held-out prediction. Their practical tradeoff is explicit:

| Model / frozen threshold | Held-out precision | Recall | F1 | False-positive rate | False positives / benign samples |
| --- | ---: | ---: | ---: | ---: | ---: |
| LightGBM, validation maximum F1 (`0.35404475335527597`) | 88.55% | 95.03% | 0.91677 | **12.3329%** | 3,062 / 24,828 |
| LightGBM, validation approximately 1% FPR (`0.8364759327803969`) | 98.31% | 73.44% | 0.84073 | **1.2647%** | 314 / 24,828 |
| Linear baseline, validation maximum F1 (`0.04778669338895734`) | 63.26% | 96.36% | 0.76374 | 56.1624% | 13,944 / 24,828 |
| Linear baseline, validation approximately 1% FPR (`0.9909584195890437`) | 89.50% | 11.56% | 0.20475 | 1.3614% | 338 / 24,828 |

The LightGBM low-FPR threshold produced 0.9929% FPR and 71.19% recall on validation, then 1.2647% FPR and 73.44% recall after the temporal shift. A validation false-positive target is not a guarantee on later data. The F1 threshold catches more publisher-labeled malware but flags more than one in eight publisher-labeled benign files. The linear baseline reached its fixed 30-iteration cap before convergence; it remains the recorded bounded baseline and was not retrained after seeing test scores.

Raw preparation took **678.02 seconds**; the two classifiers' fitting and once-only evaluation took **68.14 seconds**, using two training CPU threads. Versions were NumPy 2.4.3, scikit-learn 1.6.1 and LightGBM 4.6.0. Numerical results, true retained month/class counts and frozen choices are recorded in [dataset-manifest.json](../training/results/static-v2/dataset-manifest.json), [frozen-plan.json](../training/results/static-v2/frozen-plan.json) and [metrics.json](../training/results/static-v2/metrics.json). Reloading both saved artifacts reproduced 512 recorded predictions exactly and gave zero decision changes at both frozen thresholds; see [artifact-validation.json](../training/results/static-v2/artifact-validation.json).

The official archive is `ember_dataset_2018_2.tar.bz2`, 1,696,539,273 bytes, with publisher SHA-256 `b6052eb8d350a49a8d5a5396fbe7d16cf42848b86ff969b77464434cf2997812`. The publisher's [license at the inspected immutable revision](https://github.com/elastic/ember/blob/d97a0b523de02f3fe5ea6089d080abacab6ee931/LICENSE.txt) assigns **MIT** to the referenced data and **AGPL-v3** to its code. A copy of the publisher extractor was fetched into the ignored research cache for read-only schema/API inspection. It was never imported, executed or bundled. Big Brother's numeric projection is independently written; no publisher extractor implementation is incorporated into project code.

Inputs remain under `training/data/v2/static-ember` on D:. The compressed archive is verified in full, then streamed without extracting raw JSON to disk. Cached matrices contain only a deterministic quarter of eligible file SHA identities. Labels, appearance month, hashes, malware family and source file name are excluded from the 564 input features. Inputs contain log-scaled general/header/string counts, normalized byte and byte-entropy histograms, data-directory sizes and section summaries. This is a smaller independent projection, not the publisher's full feature-vector benchmark.

Individual JSON rows are limited to 4 MiB. Larger publisher rows are drained in bounded chunks, hashed with the rest of their archive member and excluded from features. Their observed first-field SHA-256 remains in identity exclusion; preparation stops if that header cannot be verified. Unknown labels of those excluded rows are absent from raw class counters. Archive files are never unpacked or executed, and per-file held-out predictions remain in the ignored cache.

The observed exclusions were four oversized rows (three official training, one test), 199,999 parsed unlabeled records, eight exact projected-feature duplicates within splits (four fitting, one validation, three test), and one held-out row excluded by the cross-split identity/vector check. The manifest preserves that aggregate cross-split count; it does not distinguish its SHA-identity and vector-match branches. A deterministic hash rule excluded 600,320 additional parsed labeled rows. There were no invalid numeric-feature records. The archive also contains a **127,284,141-byte plaintext publisher model**; it was hashed and ignored, never loaded or used for our models. No binary samples are present in the inspected archive member list.

A separate native-tar streaming audit confirmed **200,000 raw test records with 200,000 distinct SHA-256 identities**, zero repeated identities and zero conflicting known class-label identities. Its complete raw test-member checksum matches the preparation manifest. The one oversized test row remains included in identity counts while its label is explicitly unavailable. The [identity audit](../training/results/static-v2/identity-audit.json) used no model scores, extracted no files and exported no per-file hashes; it does not resolve near duplicates or family overlap.

Before held-out results are calculated, the experiment fixes the following protocol:

1. Use published class labels 0/1; exclude unlabeled `-1` entries.
2. Select SHA-256 identities whose first eight hexadecimal digits modulo four equal zero, independent of labels.
3. Fit only official training samples first seen through August 2018; use September–October 2018 official training samples for validation. Reserve November 2018 onward official test samples for final evaluation.
4. Remove repeated official training file hashes. Exclude all raw training file identities from held-out data regardless of the subset. Remove exact projected-feature duplicates within each split and across fitting/validation/test.
5. Fit a scaled linear logistic-loss baseline and LightGBM with fixed seed 1984 and two CPU threads. LightGBM early stopping uses validation average precision. Choose the model by validation average precision and thresholds by validation F1 and a separate validation benign-score 99th percentile.
6. Write `training/results/static-v2/frozen-plan.json` before held-out prediction. Score the held-out set once and report ROC AUC, average precision, confusion counts, precision, recall, F1, false-positive rate, log loss and Brier score at the frozen thresholds.

Month resolution is coarse. Family-disjoint generalization is not established: reliable complete families are absent for benign files, and malware families can overlap over time. Exact identity/vector checks do not eliminate every near duplicate, signer, packer or collection bias. Publisher labels are historical judgments, not new independent malware adjudications. Rates reflect the selected benchmark's prevalence and cannot become live false-alerts-per-hour estimates.

Fitting samples include publisher appearance months from January 2007 through August 2018, not only 2018. Validation contains September/October 2018 and the held-out samples contain only November/December 2018. Among retained malware records, 407 named families overlap fitting and held-out splits; 2,276 fitting, 373 validation and 164 held-out malware rows lack a family name. This experiment does not measure generalization to wholly unseen malware families.

The official extractor used LIEF 0.9.0 for version-two features and documents compatible extraction with LIEF 0.10.1. Those are older APIs; parity with modern Windows/Python and current executable formats has not been validated. Classification from publisher raw features is therefore research-only until an independently reviewed extractor reproduces the selected features on representative harmless executables and malformed PE cases. No claim about current installed applications follows from a high historical benchmark score.

The original run used the existing research Python environment containing NumPy, scikit-learn and LightGBM:

```powershell
C:\Python312\python.exe training\static_pe_v2.py --acquire --prepare --train
```

`training/static-requirements.txt` records the experiment's dependencies. They are separate from application dependencies; no static classifier package is added to the Windows installer.

This completed experiment is now frozen. Both `--prepare` and `--train` refuse to overwrite existing frozen decisions, metrics or the protected matrix cache. A separate reviewed experiment must use new versioned data/results locations and a fresh evaluation protocol. The cache freeze marker for this first run was added immediately after its completed once-only evaluation; future runs write it before their held-out prediction. No model, threshold or score was retuned after these held-out results.

For numerical reproduction, use fresh locations without deleting the original decisions or cache. The example reuses only a copy of the checksum-verified compressed feature archive; the new run verifies it again and writes separate matrices and results:

```powershell
New-Item -ItemType Directory -Force training\data\v2\static-ember-reproduction
Copy-Item -LiteralPath training\data\v2\static-ember\ember_dataset_2018_2.tar.bz2 -Destination training\data\v2\static-ember-reproduction\ember_dataset_2018_2.tar.bz2
C:\Python312\python.exe training\static_pe_v2.py --data-dir training\data\v2\static-ember-reproduction --results-dir training\results\static-v2-reproduction --prepare --train
```

Both alternate locations must be descendants of this project's D: `training/data` and `training/results` directories. Reusing an existing frozen data cache with a new results path is also refused. Reproducing fixed numerical choices does not provide a new independent evaluation: those historical held-out results are already known. Any future model search needs a separately specified untouched holdout.

`--prepare` verifies the complete archive before reading it. `--train` verifies cached matrix hashes from the dataset manifest. Research weights, frozen decisions and aggregate numerical results are in `training/results/static-v2`; data matrices and per-file predictions stay ignored on D:. The repeatable read-only serialization check is `C:\Python312\python.exe training\validate_static_pe_v2.py`; it verifies artifact checksums and prediction/decision parity with the original recorded values, without refitting or producing new classification metrics.
