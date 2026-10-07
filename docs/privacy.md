# Local data and privacy

Big Brother stores process paths, recorded command lines, activity timestamps, selected file/Registry paths, DNS queries and connection metadata in a local SQLite database. These can contain personal information or secrets. The standalone service defaults to the current user's `%LOCALAPPDATA%\Big Brother`; the packaged desktop passes its application data directory explicitly. The portable executable uses a `BigBrother-data` folder beside itself. An explicit desktop `BB_DATA_DIR` or service `--data-dir` selects another location.

No remote request is required for monitoring, scoring, replay, retrieval or deterministic explanations. A curated versioned documentation corpus and the trained model artifacts are shipped locally. Unselected processes appear in the process picker but their histories are not saved as watched sessions. Process identity and parent fields are transiently inspected to discover descendants. Unmatched Sysmon evidence stays in bounded memory for correlation and is not persisted as a whole-system history.

## Retention and deletion

The default retention is 7 days and 20,000 evidence events. Retention uses ingestion time so historical replay timestamps do not immediately discard demonstrations. Controls permit 1–90 days, 500–100,000 evidence events, a queue limit of 128–16,384, a polling interval of 0.5–10 seconds and 1–100 active sessions. The default queue limit is 4,096 and default active-session limit is 20. Limits can truncate evidence and the app records that as a gap.

Deleting a session removes its memberships and incident reports. Evidence used by another retained session remains until that session is also deleted or its retention expires. Otherwise unreferenced events, process metadata and identity aliases are removed. SQLite `secure_delete` is enabled and its write-ahead log is checkpointed after deletion and on clean exit. This is application deletion, not a forensic secure-erasure guarantee for filesystem backups, SSD wear levelling, exported reports or Windows logs.

The local database is not encrypted by this application. It inherits access protections of the selected user directory. Use account access controls and disk encryption where appropriate. Big Brother does not store API keys in this SQLite database. Optional provider tooling documents its own explicit approval, redaction and Windows credential-store behavior; it is separate from automatic collection.

## Sensitive exports and optional providers

Exporting a report writes selected session evidence and findings to the location chosen in the desktop save dialog. Reports include a notice about sensitive telemetry, fabricated replay provenance, anomaly-score interpretation and incomplete coverage. Review a report before sharing it. Exporting is not an automatic upload.

The normal application's `llm_provider` is disabled. Deterministic explanations are always available and event text is never executed or treated as instructions. The optional provider extension is separate from the monitoring pipeline. Any external provider workflow must preview and redact telemetry and receive explicit opt-in before transmission. Automatic scoring and collection never invoke that extension.

## Execution and access boundaries

**Import recording** opens a native JSON file dialog and reads normalized public or personal telemetry as inert data. It never launches recorded executables or follows recorded destinations. Imports allow at most 32 MiB, 10,000 events and 1,000 distinct processes; malformed or inconsistent identities are rejected. Session evidence and source metadata commit in one transaction. Imported paths, commands and provenance can be sensitive, just like live observations. Recording provenance is included in exported reports and removed with the last retained session or expiration. Its declared source and scenario label are not authenticated by import and never become model labels.

Normalized event content additionally has an 8 MiB budget so the generated graph, findings and export remain within the private IPC response limit. Imported recordings analyze and display all retained events up to the 10,000-event cap, preserving early reference citations. Missing PIDs stay zero/unknown with explicit uncertainty; an observed nonzero PID for the same GUID may fill process metadata without rewriting the original event. Conflicting known PIDs are rejected. Live session state and scoring use the latest 2,000 retained events; export can include older retained evidence.

Selecting an executable in a dialog only records its path. Only the explicit “Launch and watch” method starts the selected `.exe`; it uses an argument array with `shell=False`. Watching an existing process does not relaunch it. Replays contain fabricated command lines and risky behavior descriptions, but never execute those lines or create real persistence.

The Python service is a private child of Electron communicating over inherited standard input/output. It exposes no listening HTTP or TCP API. The renderer has a sandbox, context isolation and no Node execution; a narrow main-process interface validates requests and binds them to the app's own window. Both sides validate the supported method names and parameters. IPC request size is bounded. Strings from events, datasets, documents and model outputs remain untrusted data.

There is no autonomous remediation in this version: the app does not kill monitored programs, block traffic, quarantine files or delete suspected content. Test cleanup terminates only trusted processes created for the test. A separately installed Sysmon service may continue logging after the app exits; Big Brother does not delete those Windows logs or disable the service.
