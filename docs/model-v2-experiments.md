# Expanded behavioral model experiments

This experiment expands real LANL process/network/DNS prediction training. It preserves the original v1 artifacts, results and final test. It does not train a malware classifier or assign malicious labels to individual Windows log events.

## Data actually acquired

Three 32 MiB compressed prefixes from immutable Taqui mirror revision `d7a15d0d504051bfe6cbc3f65377830704e824cc` provide 17,510,711 complete records and 509,909,518 usable decoded bytes. [The frozen acquisition manifest](../training/lanl-v2-manifest.json) records source URLs, exact compressed/text SHA256, publisher full-archive hashes and expansion bounds. These are incomplete gzip archives; their full-file hashes and final gzip footers are not verified. Publisher equivalence to official archives remains a publisher claim.

The [official LANL 2015 dataset](https://csr.lanl.gov/data/cyber1/) describes the schema and public-domain waiver. Anonymous host/process identifiers contain no Windows PID or process-parent information. Flows are host observations without process attribution. This limits transfer to a watched Windows application tree.

All original experiment timestamps through second 17,910 are excluded. The new common time interval is 17,911–45,301. Host SHA256 buckets stay disjoint between training, validation and test; time intervals are also separate. Exact duplicate raw rows and partial 24-event windows are excluded. The downloaded DNS prefix contains substantial later-time data outside the common interval, which is not used.

| Split | Relative seconds | Complete 24-event windows | Hosts supplying complete windows | Next-event targets |
| --- | --- | ---: | ---: | ---: |
| Train | 17,911–34,344 | 90,235 | 4,600 | 721,880 |
| Validation | 34,345–39,822 | 11,908 | 1,494 | 95,264 |
| Fresh test | 39,823–45,301 | 8,048 | 1,400 | 64,384 |

Each window contains 16 context events and eight rolling next-event targets. Training therefore uses about nine times the original number of unique target examples. The fixed ten-token vocabulary still covers process starts/ends, DNS and network destination-port categories. Detailed Registry, file, access and ancestry evidence remains outside this model.

## Fixed experiments and selection

Two seeds (`1984`, `2026`) each fit a histogram baseline with eight centroids and two GRUs: embedding size 8 / hidden size 16, and embedding size 16 / hidden size 32. The baseline uses the same contexts/targets as the temporal models. Both GRU capacities fit on CPU with two threads, Adam learning rate 0.003, batch size 512, gradient clipping at 1.0 and a maximum of 16 epochs. Validation improvement of at least 0.0001 resets patience of three epochs. The best qualifying validation epoch is restored.

All capacities/seeds are declared before test evaluation. Minimum validation next-event negative log likelihood selects the candidate; validation's 99th-percentile maximum surprise across eight targets selects its threshold. [The selection freeze](../training/results/v2/selection-freeze.json) records artifacts and hashes before any fresh-test prediction. The test is evaluated once after the freeze, including an unchanged v1 comparison on the same new targets. Predictions are cached locally for descriptive failure analysis; they never update thresholds or weights.

Checked JSON exports use the existing standard-library runtime. No PyTorch/sklearn runtime dependency is added to the Windows application. Experimental artifacts live under `training/results/v2/models`, separate from the shipped `resources/models` directory; promotion is a separate reviewed integration step.

The measured selected model was subsequently activated by `scripts/promote_model.py`. Promotion checks the freeze hash, minimum finite validation loss, independent candidate result, threshold, weight hashes and actual runtime load before replacing the active index. Isolated tests reject changed weights, pointers, selection metadata and coordinated threshold edits before any runtime mutation. The original freeze is not a signed complete-result manifest: these consistency checks catch divergent edits but do not authenticate a repository in which every file is maliciously rewritten. Git history preserves the actual checkpoint.

## Actual frozen results

The validation-selected default uses embedding size 16 / hidden size 32, seed 2026, selected epoch 11 after 14 epochs and patience stopping. Total preparation/training/evaluation took 1,060.69 seconds (17.7 minutes). All other GRUs selected epoch 7 and stopped after 10 epochs. [Saved metrics](../training/results/v2/metrics.json) contain the complete histories, hardware and thresholds.

| Candidate | Validation NLL (nats) | Same fresh-test NLL (nats) | Test windows exceeding frozen threshold |
| --- | ---: | ---: | ---: |
| Baseline, seed 1984 | 0.732101 | 0.843113 | 83 / 8,048 |
| Baseline, seed 2026, validation-selected baseline | 0.726471 | 0.831453 | 87 / 8,048 |
| GRU embedding 8 / hidden 16, seed 1984 | 0.527905 | 0.579743 | 110 / 8,048 |
| GRU embedding 8 / hidden 16, seed 2026 | 0.529724 | 0.580987 | 112 / 8,048 |
| GRU embedding 16 / hidden 32, seed 1984 | 0.524128 | 0.572086 | 99 / 8,048 |
| GRU embedding 16 / hidden 32, seed 2026, selected default | **0.519977** | **0.571488** | 94 / 8,048 |
| Unchanged original v1 model on this same new test | — | 0.603148 | 237 / 8,048 |

The selected v2 model improves next-event loss by 5.25% relative to unchanged v1 on the same fresh targets and 31.27% relative to the fairly trained selected baseline. Both seeds favor the larger capacity. Test perplexity is 1.77090 versus original v1's 1.82786. These quantify category prediction, not malware accuracy. Window exceedance fractions (v2: 1.168%, v1: 2.945%) are unlabelled anomaly counts, not false-positive rates.

The selected JSON weights are 151,173 bytes with SHA256 `26adda072a62e5d6320686d04b7da98a2cbbdbe7c6a3559e37d8616bb025e95e`. Export probabilities agree with PyTorch on 32 actual validation contexts, with maximum error 6.71e-8. Standard-library prediction for a 16-token context measured median 8.39 ms and p95 8.74 ms across 30 actual test contexts. Final sampled training RSS was 809.38 MiB; peak RSS was not measured. These timings exclude Electron, telemetry collection and the complete eight-target session scorer.

The [external Windows check](../training/results/v2/external-windows.json) consumes 264 real recordings: 107 OTRF and 157 EVTX samples. Only 57 recordings supply complete windows, yielding 725 disjoint 24-event windows and 5,800 targets. Frozen v1 loss is 2.305962 nats; selected v2 loss is 1.274351 nats, about 44.7% lower. Threshold exceedances fall from 262/725 to 90/725. This supports better prediction transfer for the supported categories; it does not establish improved attack detection.

Only 19,867 of 986,382 normalized external events (2.014%) enter the ten-token model. About 98% are Registry, process-access, image-load, file or thread events outside its schema. Detailed evidence and transparent rules remain necessary, and a quiet model result cannot establish safety.

## Limits and external checks

The train windows contain 60 DNS-port observations and 3,919 remote-port observations; rare types still have limited support. Of these, only 17 DNS-port and 1,285 remote-port observations appear as predicted targets. No DNS-port tokens appear among fresh-test targets, so that category's loss remains unmeasured. Unknown NetFlow ports account for about 37% of training observations, a large difference from direct Windows socket telemetry. Overall loss can hide rare-type failures, so [the frozen audit](../training/results/v2/frozen-audit.json) reports conditional losses and actual exported-runtime timings for every seed/capacity.

749 real LANL red-team annotations were separately acquired and hashed. Their earliest timestamp is 150,885 seconds, outside the expanded common interval; they provide no attack labels for these training/evaluation windows. Absence of an annotation does not prove a window benign.

Independent Windows laboratory recordings are used as external domain checks after the selection freeze. OTRF and EVTX attack scenarios contain mixed background events and lack event-level malicious/benign labels or matched negative controls. Whole-host 24-event windows match the training objective; short fragments and unsupported Sysmon event types are explicitly counted. Lower prediction loss or threshold exceedance on this corpus cannot be called malware precision, recall or false-positive rate.

## Reproduction without overwriting results

Use Python 3.12 with [the training requirements](../training/requirements.txt), including the CPU PyTorch wheel. The actual run used the existing `C:\Python312\python.exe`; all newly downloaded data, cached windows and outputs stay on D:. From the project directory:

```powershell
C:\Python312\python.exe training/expand_lanl.py --prefix-mib 32
C:\Python312\python.exe training/train_v2.py --epochs 16 --patience 3 --max-train-windows 100000 --max-eval-windows 15000 --threads 2 --output-dir training/results/reproduced-v2 --cache-dir training/cache/reproduced-v2 --v1-models-dir training/results/v2/v1-original
C:\Python312\python.exe training/audit_v2.py
C:\Python312\python.exe training/evaluate_external_v2.py
.venv\Scripts\python.exe -m pytest tests/test_training_v2.py -q
```

The last two analysis commands inspect the saved original v2 experiment. The trainer refuses to replace an already frozen output directory or mix resumed candidates from different configurations. Reproduction uses the same fixed configuration and test; a new model search after seeing these test results requires a new holdout. Downloads enforce a 20% free-space reserve and a 1 GiB expansion bound per source. They never run dataset commands or executables. Raw archives and normalized recordings remain ignored by Git.
