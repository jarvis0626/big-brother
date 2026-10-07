# Public dataset research and recorded Windows scenarios

On 7 October 2026, this iteration catalogued sixteen relevant dataset families and acquired two independent Windows event-log corpora. A large dataset only helps the product when the observed features, label meaning and collection conditions match the detector. Numeric Linux syscalls, static PE headers, memory-dump features and network-flow classifiers do not become Windows Sysmon observations by concatenating their tables.

The source and license catalog is [catalog-v2.json](../training/catalog-v2.json). Every acquired archive and selected member has an immutable publisher revision, byte count and SHA-256. The normalized coverage and checksums are [corpus-v2-manifest.json](../training/corpus-v2-manifest.json). Raw archives and normalized records remain in `D:\Projects\Big Brother\training\data\v2`, ignored by Git and excluded from installer resources.

| Acquired source | Publisher revision | Usable recordings | Normalized events | Terms |
| --- | --- | ---: | ---: | --- |
| [OTRF Security-Datasets](https://github.com/OTRF/Security-Datasets) atomic Windows host logs and compound campaigns | `d9d40ef123d2c87d5d3df28c96bcab4f0faccc87` | 107 | 983,532 | [MIT license at the pinned revision](https://github.com/OTRF/Security-Datasets/blob/d9d40ef123d2c87d5d3df28c96bcab4f0faccc87/LICENSE) |
| [EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) Sysmon recordings | `4ceed2f4706daf601c212a8f91c113dd85349a2c` | 157 | 2,850 | [GPL license at the pinned revision](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/4ceed2f4706daf601c212a8f91c113dd85349a2c/LICENSE.GPL) |

The 264 unique source archives contain 1,778,087 raw records and 986,382 normalized Windows Sysmon events. Normalized JSON is about 813 MB; the entire acquisition, extracted selected archives, research metadata and normalization cache occupy about 1.57 GB. Byte-identical archives count once. Recorded laboratory adversary scenarios include background activity; a scenario's title or ATT&CK mapping does **not** label every event or process as malicious. These corpora supply independent scenario coverage and evidence investigation examples. They were excluded from behavioral model fitting and threshold selection, and cannot establish malware binary accuracy, precision, false-positive rate or safety.

Twenty-eight candidate archives were excluded with exact reasons in the manifest: fourteen had invalid UTF-8 source records; ten lacked supported GUID-identified Windows Sysmon events; three encountered filesystem access/write errors; one duplicated an already included archive. Two additional OTRF archive files were unavailable during extraction and are separately listed in the source catalog. No Defender settings were changed and unavailable files were not used.

`training/datasets_v2.py` reads inert NDJSON and uses Windows' documented [read-only offline event query](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/wevtutil) to parse selected EVTX files into Unicode XML. It never runs dataset attack commands, replays events into Windows logs, loads DLLs or opens recorded network endpoints. The parser checks source hashes and bounds archive members, expanded data, record size and event count. It retains process GUIDs with capture and host scope, UTC timestamps, observed parent references and source record IDs. Missing process starts and parents are counted; identities and ancestors are not invented. Capture-local duplicate events are removed without collapsing distinct observed command lines.

Supported investigation kinds are process start/end, network, DNS, file create/delete, registry modification, image load, process access and remote thread. The behavioral model currently consumes process start/end, DNS and network port categories. Other recorded events remain evidence for investigation and explicitly count toward unsupported model-feature coverage. Scenario labels stay in provenance outside scoring inputs.

To reproduce acquisition and normalization from the project root:

```powershell
.venv\Scripts\python.exe training\datasets_v2.py --acquire --normalize
```

The helper preserves twenty percent of the D: drive as free space, downloads only pinned official revision archives, extracts only enumerated data/metadata/license files and verifies checksums. It retains source license files locally. On another Windows machine, protections or parser behavior can change the available corpus; exclusions must remain visible, and the manifest should be compared rather than assuming identical counts.

For an actual small process-access investigation, import `training\data\v2\recordings\otrf-a28dbf708685a80e.json`: 83 unique events, eight observed processes and seven missing process creation records. For a mixed network/registry example, import `otrf-9b23288621db8a75.json`: 332 events, 34 processes, eighteen network events and one DNS event. These are actual recorded lab logs, not fabricated demonstrations. Import reads data only. The large APT29 recordings are useful for offline analysis and may exceed application import/retention bounds.

The full tiny LANL 2015 red-team annotation file was also acquired from the same immutable mirror revision as training, with the publisher's full SHA-256 and complete gzip CRC verified. Its 749 authentication annotations span 150,885–2,557,047 seconds. There are zero annotations in either the v1 interval 1–17,910 or the expanded v2 common interval 17,911–45,301. See [lanl-redteam-v2.json](../training/lanl-redteam-v2.json). Unannotated process/network windows are still not independently labeled benign. The mirror's equality to the registration-gated official original was not independently checked.

| Additional family reviewed | Relevance and current disposition |
| --- | --- |
| [LANL 2015](https://csr.lanl.gov/data/cyber1/) | Compatible process/flow/DNS sources; expanded prefixes are used by the separate behavioral training experiment. LANL provides a public-domain-style copyright waiver. |
| [LANL Unified Host and Network 2017](https://csr.lanl.gov/data/2017/) | Windows process/security events and flows; future independent production-domain transfer evaluation. Official acquisition asks registration; no attack ground truth on the inspected page. |
| [OpTC](https://github.com/FiveDirections/OpTC-data) and [corrected 2026 release](https://doi.org/10.57745/UXCWOC) | Rich Windows provenance; original access was quota-limited and undocumented transformed mirrors remain excluded. Full/corrected archives exceed this bounded experiment; identifier corrections and annotation methods require review. |
| [DARPA TC E3/E5](https://github.com/darpa-i2o/Transparent-Computing) | Public-domain experimental provenance and ground truth across several platforms. Requires a sensor-specific adapter and substantially larger acquisition. |
| [ATLASv2](https://arxiv.org/html/2401.01341v1) | Windows Sysmon/EDR and actual researcher background work plus lab attacks. Full release is 154 GB; dataset-specific terms and correct Security/REAPr label mapping need verification. The paper's CC BY license alone is not a dataset license. |
| [BETH](https://www.kaggle.com/datasets/katehighnam/beth-dataset) | Real Ubuntu honeypot process/DNS events with `sus`/`evil` annotations; publisher Kaggle API lists CC0. Linux sensor features are absent from the Windows runtime. |
| [AWSCTD](https://github.com/DjPasco/AWSCTD) | Windows syscall sequences; feature mismatch and no verified publisher license. Not acquired. |
| [CSE-CIC-IDS2018](https://www.unb.ca/cic/datasets/ids-2018.html) | Network and machine event logs; publisher permits redistribution with citation and [AWS registry link](https://registry.opendata.aws/cse-cic-ids2018/). Published labels target flows; host labels require validated correlation. |
| [CIC-MalMem2022](https://www.unb.ca/cic/datasets/malmem-2022.html) | Labeled memory features; absent from current runtime. The inspected license section did not provide an explicit grant. |
| [ADFA-WD/LD](https://research.unsw.edu.au/projects/adfa-ids-datasets) | Syscall-oriented Windows/Linux traces; inspected UNSW terms limit use to academic research and prohibit commercial use. |
| [LID-DS](https://github.com/LID-DS/LID-DS) | Linux syscall lab traces; publisher framework is GPL, dataset terms need separate review, features differ from Windows collection. |
| [EMBER](https://github.com/elastic/ember), [BODMAS](https://github.com/WhyisYoung/BODMAS), [SOREL-20M](https://github.com/sophos/SOREL-20M) | Static PE features and sample labels may support a separate static classifier. They do not train a Sysmon sequence detector; binary downloads are unnecessary. SOREL baseline inputs alone are about 78 GB. |

EMBER 2018 feature-only acquisition and a separate supervised classification experiment are now complete. Its frozen temporal held-out subset contains 49,742 samples; LightGBM achieved ROC AUC 0.97633 and average precision 0.97784. At the validation low-FPR threshold, held-out recall was 73.44% with 1.2647% false positives; the validation F1 threshold instead produced 12.3329% false positives. The [static experiment report](static-pe-experiment.md) documents both operating points, leakage checks, exact exclusions and the missing modern extractor parity. It remains separate research and supplies no live Windows behavioral accuracy claim.

The catalog is a researched, bounded source inventory rather than a claim that every security dataset on the internet was exhaustively surveyed. Dataset size, attack terminology and a high benchmark score cannot substitute for compatible runtime observations and independent deployment validation.
