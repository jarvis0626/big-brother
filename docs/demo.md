# Five-minute replay demo

Open the installed **Big Brother** shortcut, or run `release/Big-Brother-0.2.0-x64-portable.exe` from a writable folder. No administrator account, Sysmon installation or external LLM is needed for this demo.

Both scenarios contain **fabricated evidence**. Opening a replay ingests records; it never runs the named programs, creates a startup entry or contacts a destination. These fixtures demonstrate the investigation workflow and are excluded from training and accuracy evaluation.

## Ordinary activity

1. Choose **Explore a replay**, select **Ordinary activity**, then **Open replay**.
2. Confirm the **Replay · fabricated** label. The graph contains one process, the timeline contains three retained events, and there are no findings.
3. Open **Settings** to inspect telemetry coverage and the active model, `lanl2015-v2-gru-e16-h32-seed2026`. A quiet finding list does not establish safety; the model supports only process start/end, DNS and network-port categories.

## Investigation

1. Choose **Explore a replay**, select **Investigation**, then **Open replay**.
2. Follow the four-process chain: `setup.exe → installer.exe → cmd.exe → helper.exe`. The timeline contains thirteen unique events. A repeated input record is deduplicated, and out-of-order arrival does not change the recorded lineage.
3. Inspect the startup Registry event, the parent termination and subsequent helper activity. These are recorded relationships within the fixture, rather than instructions to reproduce the behaviour.
4. Open **Findings**. Expect three findings: one from the actual trained temporal model and two separately labelled transparent rules. The model's anomaly score is surprise in nats, not a malware probability. Registry and ancestry evidence support the rules but are excluded from that model's inputs.
5. Open the model finding. Read **Observed facts**, **Possible interpretations**, **Missing information** and **Suggested checks**. Click an event-ID citation to navigate to its exact timeline entry. General explanations link to supporting security documentation.
6. Choose **Export report**, save the JSON locally and review its evidence IDs, model version, replay notice and limitations before sharing it.

Close the window and reopen it from the tray's **Show dashboard** action. Inspect retained sessions under **Sessions**; they also persist across a normal app restart. Use **Stop collection and exit** to close the app. This does not stop any separately installed Sysmon service.

The Windows packaged GUI checks exercised both replay workflows, citation navigation, export, tray behaviour and restart retention. Results are saved in [packaged-gui-smoke.json](../artifacts/packaged-gui-smoke.json). These checks verify application behaviour, not malware-detection accuracy.
