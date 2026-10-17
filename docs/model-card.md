# Behavioral model card

The active model is **Expanded LANL temporal GRU event predictor**, version `lanl2015-v2-gru-e16-h32-seed2026`. It was actually trained on expanded real process, network-flow and DNS telemetry and evaluated on disjoint hosts and later times. Its output is event-sequence surprise as negative log likelihood in nats, not the probability of malware. Low scores do not establish safety.

The research question is whether temporal event order improves next-event prediction over a histogram baseline. These results do not establish improved malicious-behavior detection from process/file/network graphs. The LANL acquisition has no trustworthy event-level attack labels, file evidence or process-family identities; richer interface evidence does not become a model input.

## Active v2 model and inputs

Ten fixed categories represent process start, process end, DNS, and seven destination-port groups: web (80/443/8080/8443), SMB (139/445), remote services (22/3389), DNS (53), other service ports below 1024, high ports, and unknown ports. Usernames, process names, addresses, command lines and host identifiers do not become predictors. The model ignores file, Registry, process-access, image-load and remote-thread events.

The baseline learns eight centroids of 16-event category histograms with Laplace-smoothed next-category distributions. The active neural model uses an embedding of size 16 and a PyTorch GRU with 32 hidden units. Four real GRUs cover two capacities and two seeds; all use the same training examples as the baselines. Adam learning rate is 0.003, batch size 512, clipping threshold 1.0, maximum 16 epochs and validation patience of three epochs. Seed 2026, epoch 11 was selected after 14 epochs by validation loss. The other three runs selected epoch 7.

The expanded acquisition includes 17,510,711 complete records from three pinned 32 MiB compressed prefixes. After excluding every original v1 timestamp and separating hosts/times, training uses 90,235 complete windows and 721,880 target examples, about nine times v1. Validation uses 11,908 windows and the new final test uses 8,048 windows / 64,384 targets. Each window contains 16 context events and eight rolling next-event targets. Threshold 7.014227390289307 nats is the validation 99th percentile of maximum target surprise, frozen before test.

| Measured result on the same new holdout | Selected expanded baseline | Unchanged v1 GRU | Active v2 GRU |
| --- | ---: | ---: | ---: |
| Validation mean next-event loss, nats | 0.726471 | Not used for v2 selection | 0.519977 |
| Fresh-test mean next-event loss, nats | 0.831453 | 0.603148 | 0.571488 |
| Fresh-test perplexity | 2.296654 | 1.827863 | 1.770900 |
| Frozen anomaly threshold, nats | 6.684504 | 6.423330 | 7.014227 |
| Test windows exceeding threshold | 87 / 8,048 | 237 / 8,048 | 94 / 8,048 |
| Unlabelled window exceedance fraction | 1.081% | 2.945% | 1.168% |

V2 improves next-event prediction loss by 5.25% relative to unchanged v1 and 31.27% relative to the fairly trained expanded baseline. Both seeds favor the larger capacity. The fractions above count unlabelled windows and are never false-positive rates. Precision, recall, F1, PR-AUC, detection latency and false alerts/hour remain unmeasured for the behavioral detector.

Complete histories, provenance, split details and reproducible commands are in [the v2 experiment report](model-v2-experiments.md) and [saved metrics](../training/results/v2/metrics.json). The [selection freeze](../training/results/v2/selection-freeze.json) precedes fresh-test evaluation; the [promotion record](../training/results/v2/promotion.json) identifies the checked artifact subsequently activated in the application.

## Export and measured cost

Active weights contain 151,173 JSON bytes with SHA256 `26adda072a62e5d6320686d04b7da98a2cbbdbe7c6a3559e37d8616bb025e95e`. Standard-library inference reproduces PyTorch probabilities with maximum error 6.71e-8 across 32 actual validation contexts. The runtime validates hash, feature schema, dimensions, numerical values and threshold; missing/corrupt/incompatible artifacts expose `unavailable`. Transparent rules never replace an unavailable model.

Preparation, all four GRUs, both baselines and final evaluation took 1,060.69 seconds on Windows 11 with an AMD Ryzen 7 5800H, 16 logical CPUs, CPU PyTorch 2.10.0 and NumPy 2.4.3. Training used two CPU threads. Final sampled training RSS was 809.38 MiB; peak memory was not measured. One 16-event prediction measured median 8.39 ms and p95 8.74 ms across 30 actual test contexts. These measurements exclude Electron, collection and the complete eight-target scorer. The application needs no separate PyTorch or sklearn installation; JSON inference uses standard-library arithmetic.

The application evaluates up to eight recent supported targets, takes their highest surprise and links context/target event IDs as evidence. Since app v1.1.0, a score requires 16 preceding supported events plus a new target; shorter contexts return no score. Pending and closing TCP polling snapshots remain evidence but do not enter the reference comparison. Repeated rolling scoring of application sessions is not calibrated by the disjoint-window threshold. Scores above that threshold appear as neutral Behavior notes, separate from transparent rule Findings; they are not Windows threat classifications. The model weights, threshold and frozen research results are unchanged. The model has no destination reputation, encrypted payload contents or game-specific trust knowledge. The new [everyday-data audit](benign-data-audit.md) explains why an acquired Windows feature dataset was excluded and how private diagnostic holdouts stay outside fitting and calibration.

## External Windows recordings and remaining limits

An external check uses 264 real, inert Windows laboratory recordings: 107 OTRF and 157 EVTX samples. Only 57 supply complete supported windows, yielding 725 windows / 5,800 targets. Unchanged v1 prediction loss is 2.305962 nats; v2 is 1.274351 nats. Threshold exceedances are 262/725 and 90/725 respectively. These are domain-transfer measurements, not malware precision or recall: scenario annotations describe recorded adversary emulation mixed with background, with no event-level labels or matched benign controls.

Only 19,867 of 986,382 normalized external events (2.014%) enter the model. About 98% are outside the feature schema, especially Registry, process-access and image-load events. Full results and counts appear in [external-windows.json](../training/results/v2/external-windows.json). Lower prediction surprise on an attack-lab mixture does not prove better threat detection. Detailed observed evidence and transparent rules remain necessary, and a quiet finding list cannot establish safety.

Train windows include 60 DNS-port observations, only 17 as predicted targets; this fresh test has no DNS-port targets. Remote-port examples increased but remain sparse. Unknown NetFlow destination ports account for about 37% of training observations and differ from direct Windows socket telemetry. The [frozen per-token audit](../training/results/v2/frozen-audit.json) reports conditional losses rather than concealing rare/absent categories in a single average.

The model learns host-wide 2015 enterprise activity. A watched process tree is a narrower stream, and polling can miss brief processes/connections. Anonymous LANL process records contain no PID/parent identities and network flows have no process attribution: the application records ancestry/attribution as collector evidence, not learned graph reasoning. Source coverage, personal Windows activity, short contexts, rare ports and repeated scoring can change alert rates.

749 independently hashed LANL red-team annotations start at second 150,885, beyond this experiment's common interval ending at 45,301. They provide no attack labels for these windows; absence of an annotation does not prove benign activity. A meaningful next research step is independent benign Windows recordings with richer provenance features and campaign-level holdouts, followed by properly scoped attack/control evaluation. More epochs on the existing ten-category vocabulary do not address its feature gap.

Deterministic reference rules separately flag observed behaviors such as startup-entry changes or activity after a parent exits. They have distinct evidence and scoring labels, no trained probabilities and no measured malware accuracy. Fabricated replay fixtures and harmless simulator applications validate investigation paths; they are not detector training, malware samples or real-world accuracy data.

## Frozen historical v1 results

The original `lanl2015-v1-seed1984` model, artifacts, metrics and release tag remain preserved. Its 8-dimensional embedding / 16-unit GRU used eight epochs, seed 1984, CPU threads 2 and Adam learning rate 0.005. Its original final test is different from the new v2 holdout and must not be used for a direct before/after improvement claim.

| Historical v1 measurement on its original holdout | Feature baseline | Temporal GRU |
| --- | ---: | ---: |
| Validation mean next-event loss, nats | 0.862721 | 0.595777 |
| Original test mean next-event loss, nats | 1.119207 | 0.601077 |
| Original test perplexity | 3.062425 | 1.824083 |
| Validation anomaly threshold, nats | 5.712149 | 6.423330 |
| Original test windows exceeding threshold | 29 / 1,486 | 24 / 1,486 |
| Original test unlabelled exceedance fraction | 1.952% | 1.615% |

That final test contains 11,888 target predictions. Original training/preparation took 30.55 seconds; neural fitting took 23.08 seconds and baseline fitting 0.45 seconds. Final sampled RSS was 537.00 MiB, with peak unmeasured. Neural weights are 43,811 bytes and baseline weights 4,917 bytes. Original standard-library prediction measured median 2.740 ms / p95 2.970 ms across 30 samples. Export maximum probability error was 2.822e-7 across 32 validation contexts.

[Original metrics](../training/results/metrics.json) and [preserved original model snapshot](../training/results/v2/v1-original/active.json) retain these facts. Reproduce the historical pipeline in a separate checkout at tag `v0.1.0`; its training command writes `resources/models` and should not be run over the active v2 application. Training data has the LANL public-domain waiver described in the [dataset card](dataset-card.md); raw archives/checkpoints are not bundled in the application.
