# Big Brother implementation plan

Date: 2026-10-07. Repository identifier: `big-brother`; Python identifier: `big_brother`.

## Milestones

1. Inspect Windows and development tooling; connect Codewatch. Complete: clean workspace, Windows 11 26200, Ryzen 7 5800H (8 cores/16 threads), 32 GB RAM, Python 3.12.3, Node 22.17.1. AMD graphics; CPU training selected.
2. Build private JSON-lines IPC between a sandboxed Electron renderer, Electron main, and a frozen Python service. No listening network API. SQLite persistence and explicit user actions for launch/watch.
3. Implement process polling with honest coverage and optional read-only Sysmon Event Log ingestion. Never install or configure Sysmon silently. Stable process identities, bounded histories, recorded evidence, deterministic explanations and export.
4. Research official public dataset provenance and acquire a bounded sample, with manifests and held-out evaluation. Train a feature baseline and a temporal neural experiment. Ship actual model artifacts; score provenance and domain limitations remain visible.
5. Build React/TypeScript dashboard with process graph, timeline, findings, replay, session history, settings and tray controls.
6. Test identity, ordering, citations, model schemas, split leakage, IPC security, Windows harmless workloads and packaged startup. Build NSIS installer and portable Windows executable.
7. Record exact results and remaining limitations in README, model/dataset cards, architecture/privacy docs and HANDOFF.md.

## Decisions and constraints

- Python service is a private child process reached through narrowly validated Electron IPC. Renderer has context isolation and sandbox enabled, with no Node access.
- Replay is explicitly fabricated and never used to report real-world detection accuracy.
- Models are trained separately from packaged inference. Public telemetry can differ substantially from personal Windows activity; scores are anomaly scores, not probabilities.
- Sysmon requires a privileged service/driver and its licence; app only reads an existing configured channel. Setup is explicitly initiated by the user. Process polling remains available with reduced coverage.
- No remote LLM or paid API is necessary. Evidence-grounded templates are the core explanation path; remote transmission requires opt-in and review.
- After the user's cleanup and instruction to resume, D: has 240.9 GiB free of 914.1 GiB and C: has 118.8 GiB free of 456.1 GiB. Keep all project datasets, training outputs and download/build caches on D:. Preserve at least 20% free space; use bounded dataset samples and reserve 10–15 GiB for this development run.
- npm.ps1 is blocked by the user's PowerShell policy; use npm.cmd without modifying that policy.

## Component contract

`backend/service.py` reads JSON lines `{id,method,params}` and writes `{id,result}` or `{id,error}` only. No logging to stdout. Methods: `state`, `list_processes`, `watch`, `launch`, `replay`, `pause`, `stop`, `settings`, `delete_session`, `export`, `shutdown`. `state` params may contain `session_id`. `watch` takes `pid`; `launch` takes `path`; `replay` takes optional `scenario` (`investigation` or `ordinary`). `pause` takes `session_id,paused`; `stop` takes optional `session_id` (otherwise all collection). `settings` accepts only supported settings. `export` returns a report object/string for Electron to save via dialog.

State: `{sessions,session,events,processes,incidents,collector,model,settings,coverage}`. Sessions: `{id,name,mode,status,started_at,ended_at,root_key,ancestry_complete}`. Processes: `{key,pid,parent_key,name,image,command_line,started_at,ended_at,uncertain}`. Events: `{id,session_id,process_key,parent_key,pid,timestamp,ingested_at,kind,image,command_line,details,source,source_record_id,uncertain}`. Incidents: `{id,session_id,title,severity,score,score_kind,model_version,event_ids,explanation:{observed,interpretations,missing,suggested,documentation}}`; observed entries have `text,event_ids`. Coverage entries: `{kind,status,backend,detail}`. Collector: `{status,backend,gaps,dropped_events}`. Model includes `name,version,status,threshold,limitations`.

Packaging resources: `resources/models/`, `resources/knowledge.json`, `resources/replays/`; frozen service loads these using CLI `--resources` and database using `--data-dir`. Python CLI supports `--self-test` without a GUI. UI assets use an original SVG eye and generated ICO sizes.
