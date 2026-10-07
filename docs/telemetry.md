# Telemetry and setup

Big Brother reads observed metadata. It is an investigation tool, not an antivirus or a sandbox. Missing events and an empty finding list do not establish safety.

The packaged application works without Python, Node, a database server, or Sysmon installed separately. Its built-in process collector has reduced coverage. Broader file, Registry and DNS evidence requires an existing configured Sysmon service and driver, appropriate Event Log access, and suitable filters.

## Capability matrix

| Evidence | Built-in Windows polling | Existing Sysmon channel | Permissions and blind spots |
|---|---|---|---|
| Process identity | PID plus process creation time | Process GUID, with creation-time association to selected roots | Some protected processes deny metadata access. PID alone is never a reliable identity. |
| Process start / end | Snapshot observation; termination time approximate | IDs 1 and 5 if recorded | Short-lived children between snapshots can be missed. |
| Parent / child chain | Current parent IDs with creation-time checks | ParentProcessGuid on ID 1 | An already-running root is labelled incomplete; missing ancestry is not invented. |
| Network connections | Per-process connection snapshots, direction unknown | ID 3 if configured | Sysmon network logging is disabled by default. Neither backend records traffic contents. |
| DNS queries | Unavailable | ID 22 if configured | A readable channel does not demonstrate DNS coverage. |
| File creation / deletion | Unavailable | IDs 11, 23 and 26 if configured | Selected recorded changes only; no full-disk scans or complete file reads. |
| Registry changes | Unavailable | IDs 12–14 if configured | Startup rules inspect recorded target paths. No Registry changes are performed. |
| Process access / raw-device reads | Unavailable | IDs 10 / 9 if configured | General file-read visibility is unavailable. |
| Encrypted traffic contents / complete command history | Unavailable | Unavailable | Recorded command lines describe process creation or a later snapshot, not every command executed. |

Sysmon status is initially “not checked yet” until a watch is started. When its channel is readable, event categories remain `configuration_unknown`: Big Brother does not guess which filters the administrator enabled. Polling evidence remains explicitly partial.

## Optional Sysmon setup

Use the Settings link to the [official Microsoft Sysmon page](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon). Review the current supported Windows versions, download, licence and configuration documentation there. The documentation inspected on 7 October 2026 describes Sysmon as a service and driver and identifies Windows 11 or later and Windows Server 2019 or later.

An administrator may install and configure Sysmon using the documented `-i` and `-c` options after independently reviewing the licence and the selected XML filters. Big Brother never executes these privileged setup commands. Enabling broad network, file or Registry logging can substantially increase the separate Windows Event Log's volume. In particular, ID 23 may archive deleted files; ID 26 records deletion without that archive behavior. Big Brother neither changes nor manages that archive.

After setup, start a new watch. The app opens only the local `Microsoft-Windows-Sysmon/Operational` channel using Microsoft's [EvtQuery](https://learn.microsoft.com/en-us/windows/win32/api/winevt/nf-winevt-evtquery), EvtNext and EvtRender APIs through `ctypes`. It never opens a remote Event Log session, installs a driver, escalates privileges, or reconfigures Windows auditing. If access fails, the application continues with plainly labelled reduced polling.

## Identity, ordering and limits

The local database stores source event identifiers, source timestamps in UTC, ingestion timestamps, uncertainty flags and supporting event IDs. Record identifiers are scoped by a persisted source epoch, avoiding collision after a detected log reset. Duplicate source records are suppressed. Delayed creation records can repair parent links, and a descendant stays attached after its parent exits.

Selected roots are associated with Sysmon GUIDs only when a bounded, process-ID-filtered creation lookup agrees with the Windows creation time. Subsequent Sysmon ancestry uses GUIDs. Unmatched Sysmon records are retained temporarily in a bounded 4,096-record correlation buffer; unrelated processes are not imported into the database.

Windows process-parent snapshots use the native Toolhelp API. Only selected chains require detailed creation-time/path/command-line queries. A bounded queue separates collection from SQLite ingestion and model inference. Settings control the queue, event retention, poll interval and maximum active sessions. Queue overflow and retention truncation produce visible gaps rather than an implicit claim of complete coverage.

An EventRecordID cursor survives app restarts. Interrupted sessions are marked interrupted. Reconnection, detected channel reset and reading failures are recorded. There is a crash window between reading a source record and committing queued evidence; the reconnection gap explicitly warns that such evidence may be lost. Sysmon service restarts and missing event filters cannot always be distinguished from inactivity.

## Controls and validation

“Pause analysis” leaves evidence collection running and stops new scoring for that session. “Stop monitoring” stops the app's selected sessions. Exiting terminates the app's own collector. These controls do not stop a separately installed Sysmon service. Closing the dashboard follows the tray preference.

Actual Windows validation uses trusted Python processes, temporary files, a loopback HTTP server, normal exits and a child that continues connecting after its parent exits. The test verifies that the recorded process chain and later network events remain attributed to the watched session. Temporary-file creation is generated but is not claimed as collected file telemetry when only polling is available. The workload cleans up the processes it creates. Live Sysmon ingestion is implemented and fixture-tested; live Sysmon service telemetry was not verified because this environment has no configured channel.

Reproduce the core and live checks with:

```powershell
.\.venv\Scripts\python.exe -m pytest tests/test_backend_storage.py tests/test_backend_service.py tests/test_backend_telemetry.py -q
```

The observed result after trained model integration and queued-evidence stop checks was **21 passed in 12.98 seconds** on Windows 11 26200. The first run found and corrected a checkpoint transaction error and a slow full-system parent enumeration. A measured psutil snapshot took 4.7 seconds for 345 processes; it was replaced with native parent snapshots to make the test's short-lived parent observable. The service `--self-test` then passed with 13 unique events, 4 reconstructed processes and 3 findings, including actual trained model inference. Its fabricated late connection uses a rare destination-port category to demonstrate the fixed model threshold; the fixture is excluded from training and evaluation.

Performance workloads and measurements are generated by `scripts/benchmark.py`; inspect the recorded benchmark artifact for hardware, durations and measured overhead. These measurements describe the tested workload rather than a universal resource guarantee.
