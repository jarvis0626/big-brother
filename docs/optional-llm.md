# Optional model commentary

Core detection, process graphs, evidence retrieval and explanations work without a language model. The app makes no remote requests for monitoring or inference. The optional developer CLI supports a local Ollama-compatible provider or a user-configured HTTPS provider implementing the same `/api/generate` protocol. It returns separate **unverified supplemental commentary**. Recorded facts and their deterministic citations remain authoritative; this commentary never creates incidents or causes actions.

Provider protocol: [Ollama official API](https://docs.ollama.com/api). Stored remote credentials use [Windows Credential Manager](https://learn.microsoft.com/en-us/windows/win32/api/wincred/), never SQLite, configuration files or renderer storage. No provider/model is installed, downloaded or called automatically. End users do not need the CLI or a provider for the core application.

1. Export a JSON report in the app. Generate a preview without transmitting anything:

   `.venv\Scripts\python.exe scripts/explain_llm.py --report artifacts/report.json --model YOUR_LOCAL_MODEL`

2. Review `artifacts/llm-preview.json` in full. Automatic redaction removes common username paths, email addresses and secret arguments; it can miss personal data and secrets. The packet includes at most 100 events and 10 existing explanations. The command prints its SHA256 hash.

3. To explicitly approve this exact preview and use a provider you already run locally:

   `.venv\Scripts\python.exe scripts/explain_llm.py --report artifacts/report.json --model YOUR_LOCAL_MODEL --send --approve-sha256 REVIEWED_HASH`

4. A remote provider requires `--endpoint https://YOUR_HOST/api/generate --remote-opt-in` in both preview and send commands. Store an optional credential through a hidden prompt:

   `.venv\Scripts\python.exe scripts/explain_llm.py --endpoint https://YOUR_HOST/api/generate --remote-opt-in --store-key`

Any changed packet invalidates approval. HTTP redirects and environment proxies are disabled so they cannot reroute approved local data. Requests and responses are bounded, and no LLM tools or execution APIs exist. Supplemental output is saved in `artifacts/llm-commentary.json`, separate from application findings. Use Windows Credential Manager to remove stored credentials.

Actual local/remote LLM generation requires a separately running provider and model. Provider transport was tested with harmless local test responses; no local telemetry was sent to a real remote provider during development.
