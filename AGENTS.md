# Project instructions

Build and maintain Big Brother as a Windows observation and investigation app. Preserve source work, keep collected evidence local by default, and treat replay fixtures as fabricated. Keep model scoring distinct from transparent rules and never equate a quiet finding list with safety.

## Major-change GitHub checkpoints

The user explicitly requested on 7 October 2026 that substantial changes be pushed to a **private** GitHub repository. This authorization persists across work on this project. After a tested major implementation, model integration, packaging milestone or substantial fix, create a descriptive commit and push it to `jarvis0626/big-brother`. Routine small edits can be combined into the next meaningful checkpoint. Do not ask for approval again for these authorized milestone pushes.

Use `scripts/github_milestone.py --message "Describe the completed major change"` after reviewing the candidate files and running appropriate checks. The script verifies private visibility immediately before pushing, audits source candidates and verifies the remote commit. It uses Git Credential Manager without writing or displaying credentials. Never force push, publish publicly, change repository visibility, overwrite unrelated work, or commit local telemetry, raw datasets, cached downloads, credentials or generated installer binaries. Keep package artifacts local unless the user separately authorizes a private release upload.

Use Codewatch for significant steps, commands and observed test results. Credentials, headers, environment values and private reasoning must never be sent to Codewatch. If GitHub authentication is unavailable, preserve the local tested commit, report the concrete authentication blocker, and continue project work.

## Working conventions

Use `npm.cmd` under PowerShell; do not change persisted user or system execution policy. The documented build/test helpers use a process-scoped PowerShell policy override without changing those settings. Keep development downloads, training caches and temporary build work under this project's D: drive. Normal installed application data follows the documented user-data location; the portable application uses its adjacent data folder.

Run appropriate verification before milestone pushes. The Windows harmless workload uses only trusted Python processes, temporary files and loopback traffic. Do not run malware, disable Defender or create real startup persistence for testing. The application only reads an already configured Sysmon channel; installing or changing its privileged service/driver remains an explicit user/admin setup action.
