# Private version history

The project is backed up to the private repository [jarvis0626/big-brother](https://github.com/jarvis0626/big-brother), as explicitly requested by the user on 7 October 2026. Substantial tested changes are committed and pushed at engineering milestones.

The first source milestone, [8651940](https://github.com/jarvis0626/big-brother/commit/865194034e38a57e7565ef3af69946b0d9193c2e), was pushed and its remote SHA verified on 7 October 2026. It contains the Windows app, local evidence backend, actual trained temporal detector, replay, privacy documentation and private-checkpoint tooling. The candidate audit covered 81 files totaling 2,359,740 bytes. Five focused checkpoint guardrail tests passed; generated package testing continues in the next milestone.

The completed Windows delivery is tagged `v0.1.0`. It adds verified installer/portable package workflows, final GUI evidence, immutable dataset-provenance guards and the factual handoff. Browse [commits](https://github.com/jarvis0626/big-brother/commits/main/) to compare milestones. To inspect the release without changing the working checkout:

```powershell
git fetch origin --tags
git worktree add '../Big Brother-v0.1.0' v0.1.0
```

Use a new destination folder for a different historical commit. Each source checkpoint can be rebuilt with its own instructions and saved weights; generated package checksums identify the local delivered executables.

Source code, configuration, curated documentation, trained inference artifacts, experiment summaries and meaningful tests belong in Git. Dependency directories, raw public telemetry downloads, local observation databases, caches, development scratch files and generated installation packages are excluded. Private visibility does not make sensitive local telemetry or credentials suitable for source control.

Run a source audit without a network request:

```powershell
.\.venv\Scripts\python.exe scripts/github_milestone.py --audit
```

Create or verify the authorized private repository and origin without committing:

```powershell
.\.venv\Scripts\python.exe scripts/github_milestone.py --prepare
```

After reviewing and testing a substantial change:

```powershell
.\.venv\Scripts\python.exe scripts/github_milestone.py --message "Describe the tested major change"
```

The helper checks that the credential belongs to the configured owner, verifies repository visibility through the [official GitHub repository REST API](https://docs.github.com/en/rest/repos/repos#create-a-repository-for-the-authenticated-user), stages reviewed source candidates, creates a normal commit and pushes without rewriting history. It confirms the remote branch SHA matches the local commit. Git Credential Manager handles Git authentication; API authentication is obtained internally and retained only in memory. Tokens are never printed, placed in URLs or stored in project files.

An authentication or permission failure leaves local work intact. Sign in through Git Credential Manager and retry. If an existing origin points somewhere else or the target is public, the helper refuses to push and preserves existing configuration.

Generated installers and portable executables remain in the local `release/` directory. Source milestones do not automatically upload binary releases or alter repository visibility.
