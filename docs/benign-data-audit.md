# Better everyday Windows behavior data

Normal online games need to contact servers. Age of Empires II: Definitive Edition's [official multiplayer guide](https://support.ageofempires.com/hc/en-us/articles/360047306372-How-do-I-create-a-multiplayer-match-in-Age-of-Empires-II-Definitive-Edition) describes online lobbies and server regions. A connection being unusual to a 2015 enterprise model does not establish a threat. A game's name, a port number or a server-looking hostname also does not prove that every connection is legitimate.

The important question is whether the training data describes the same things that the app observes. The current behavioral model learns ordered host-wide process, DNS and network-port categories from LANL telemetry. A Windows process watch instead observes one application tree, often through connection snapshots. A TCP connection attempt, an established socket and a completed flow are different observations. More records from an incompatible source cannot repair those collection semantics.

## New source actually acquired and audited

The [SILRAD-1.0 publisher release](https://zenodo.org/records/17104902), DOI `10.5281/zenodo.17104902`, is a small Windows 11 Sysmon feature dataset. The [publisher's description](https://github.com/JamilIsp/SILRAD-dataset/tree/SILRAD-1.0) says the goodware portion includes benign applications, games and utilities. The [publisher metadata API](https://zenodo.org/api/records/17104902) explicitly declares the data license **CC BY 4.0**. The archive is 3,587,892 bytes; its published MD5 was verified, and the downloaded bytes additionally have SHA-256 `4eaead41122e4519201dda7e834a0be874599bbe57c7be0263893e8c302b591b`.

The acquisition is data-only: no executable samples, downloaded code execution or telemetry upload. The outer ZIP and source metadata stay in ignored `training/data/v3/silrad` on D:. Three nested CSVs totaling 179,381,225 uncompressed bytes were streamed for analysis without extracting copies to disk. Exact results, source URLs, hashes and column names are in [the audit manifest](../training/benign-v3-manifest.json).

| CSV | Rows | Publisher class 0: goodware | Publisher class 1: ransomware |
| --- | ---: | ---: | ---: |
| `fasttext-all-nofamily.csv` | 196,840 | 176,130 | 20,710 |
| `fasttext-trainmodel.csv` | 39,999 | 38,818 | 1,181 |
| `fasttext-testmodel.csv` | 156,841 | 137,312 | 19,529 |

These are publisher labels, not independently verified security judgments. The publisher describes separately collected ransomware runs and benign activity stitched into a stream. The feature release lacks timestamps, original run IDs and all destination IP, destination port, protocol and TCP-state columns. The names `ProcessGuid`, `ProcessId`, `ParentProcessGuid`, `Image` and related fields are present, but inspected rows contain numeric feature projections. Across the full release, **zero** values in the process GUID columns match original GUID syntax, and **zero** values in the PID columns are nonnegative integer strings. Their original identity/encoding cannot be assumed or recovered from these columns alone.

An exact feature-row comparison, excluding the class label, found **333 distinct rows shared between the supplied train and test CSVs**. The full CSV also contains 23,560 repeated feature rows. Identical transformed features do not necessarily mean identical original activities, but treating the supplied split as independent process runs would be unjustified. The audit cannot establish chronological, application or campaign independence because the necessary original metadata is absent.

**Disposition: excluded from the shipped behavioral model's training, threshold selection and accuracy estimates.** This dataset cannot reconstruct process-scoped network sequences or distinguish a `SYN_SENT` polling snapshot from an established connection. It may support separate categorical Sysmon research after the feature transformations, grouped split and runtime extraction are validated. Downloading it does not mean it was used to retrain the app.

To repeat the bounded audit:

```powershell
C:\Python312\python.exe training/audit_benign_v3.py --acquire
.venv\Scripts\python.exe -m pytest tests/test_benign_data_v3.py -q
```

After acquisition, omit `--acquire` to audit the local archive again. The helper verifies the pinned release size and publisher checksum, permits only enumerated README/CSV ZIP members, limits response and member sizes, and preserves at least 1 GiB of free disk space. It does not change any model artifact or threshold.

## Other primary sources reviewed

| Source | Useful benign activity | Why it is not a drop-in game baseline |
| --- | --- | --- |
| [DARPA OpTC publisher](https://github.com/FiveDirections/OpTC-data) | Explicit benign Windows 10 collection period, process-attributed eCAR host/flow records; publisher releases the data into the public domain. | Approximately 1 TB compressed; synthetic enterprise background, a different sensor, and [documented process-identity/path errata](https://github.com/FiveDirections/OpTC-data/blob/master/errata.md). A bounded host/day adapter and independent host/day split are necessary. No large download was performed in this audit. |
| [ATLASv2 authors' report](https://arxiv.org/html/2401.01341v1) | Four days of manually generated ordinary researcher activity, including web browsing, meetings, Office and Discord; Sysmon and other sensors. | Two Windows 7 virtual machines, 154 GB, limited software diversity and repeated VM startup footprints. The paper's CC BY license does not itself establish a license for the separately hosted raw data. Dataset-specific license and label mapping must be checked before acquisition. |
| [Previously acquired OTRF/EVTX recordings](datasets-v2.md) | Real Windows event-log evidence, including mixed ordinary background activity. | Attack-scenario provenance does not identify individual background events as benign. These recordings lack matched modern game/control sessions and remain separate external investigation examples. |

The next useful training corpus should come from **the same collector and process scope as deployment**, with sessions for ordinary games, launchers, browsers, updates and background helpers. Preserve whether events came from snapshots or configured Sysmon, TCP states, process creation identities, capture gaps and app/run boundaries. Keep private identifiers local or remove them before any authorized sharing. Treat known ordinary workload sessions as scoped controls, rather than silently trusting arbitrary activity as benign.

Split by complete application runs, days and software/version groups before fitting. Keep at least one later run and an unseen application family out of both training and threshold selection. Evaluate false notices per hour on those scoped ordinary controls alongside separate attack/control tests; never call unlabeled exceedance rates a false-positive rate. The current incident report can be a regression case, but tuning to that case and reporting it as independent accuracy would be misleading.

## Changes made without retraining

V1.1.0 keeps the original model weights and threshold. It uses established polling TCP snapshots for scoring while retaining attempts and closing snapshots as evidence. It also waits for sixteen preceding supported events plus a new event before producing a reference score. These changes align the inputs with the documented comparison conditions; they do not establish malware accuracy or fully calibrate host-wide LANL telemetry for individual Windows applications.

Differences from the reference sample appear as neutral **Behavior notes**, outside the rule-based **Findings** count. The **Online connections** replay demonstrates this distinction with fabricated data. It is not a real game recording, a training sample or an independently labeled accuracy benchmark.

## Local cases for diagnosis

An explicit local helper can preserve the structure of one reported case while reducing private identifiers:

```powershell
.venv\Scripts\python.exe scripts/local_behavior_dataset.py --database "D:\Private\BigBrother-data\big-brother.sqlite3" --session "session_ID_from_your_report"
```

Both arguments are required; the example values are placeholders. Choose a live-observation session explicitly, using its `session.id` from the local JSON report. The helper reads the selected database without modifying it and writes only to ignored `training/data/v3/local` on D:. It exports event order, coarse categories, source/snapshot indicators, TCP states and capture-local process relationships. It removes original names, paths, commands, addresses, process/session identifiers and timestamps. Even coarse sequences can reveal patterns, so this file remains local.

Every output has role `diagnostic_holdout` and label `user_reported_expected`. It is excluded from fitting, calibration and threshold selection, and it is never uploaded automatically. Expected activity reported by a user is not independently verified benign ground truth. The format is separate from imported app recordings. This helper supports private regression diagnosis; it does not retrain or silently teach the app to trust the selected program. [Detailed usage](development.md#local-diagnostic-holdouts).
