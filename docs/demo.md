# Five-minute replay demo

Open the installed **Big Brother** shortcut, or run `release/Big-Brother-1.1.0-x64-portable.exe` from a writable folder. No administrator account, Sysmon installation or external LLM is needed for this demo.

All three scenarios contain **fabricated evidence**. Opening a replay ingests records; it never runs the named programs, creates a startup entry or contacts a destination. These fixtures demonstrate the investigation workflow and are excluded from training and accuracy evaluation.

## Ordinary activity

1. Choose **Explore a replay**, select **Ordinary activity**, then **Open replay**.
2. Confirm the **Replay · fabricated** label. The graph contains one process, the timeline contains three retained events, and there are no findings.
3. Read the warm-up explanation under **Behavior notes**. The model requires sixteen preceding supported events and one new event; this short fixture does not produce a reference score or model note.
4. Open **Settings** to inspect telemetry coverage and the active reference model, `lanl2015-v2-gru-e16-h32-seed2026`. A quiet finding list does not establish safety; the model supports only process start/end, DNS and network-port categories.

## Investigation

1. Choose **Explore a replay**, select **Investigation**, then **Open replay**.
2. Follow the four-process chain: `setup.exe → installer.exe → cmd.exe → helper.exe`. The timeline contains thirteen unique events. A repeated input record is deduplicated, and out-of-order arrival does not change the recorded lineage.
3. Inspect the startup Registry event, the parent termination and subsequent helper activity. These are recorded relationships within the fixture, rather than instructions to reproduce the behaviour.
4. Open **Findings**. Expect two transparent rule findings, covering the startup change and surviving child. Registry and ancestry evidence support these rules and are excluded from the model's inputs. The original thirteen-event fixture is too short for a model comparison, so **Behavior notes** shows a warm-up explanation and no model note.
5. Open a rule finding. Read **Observed facts**, **Possible interpretations**, **Missing information** and **Suggested checks**. Click an event-ID citation to navigate to its exact timeline entry. General explanations link to supporting documentation.
6. Choose **View all evidence** to return to the overview, or **Export report** to save its evidence and explanations as local JSON.

## Online connections

1. Choose **Explore a replay**, select **Online connections**, then **Open replay**.
2. Confirm the fabricated-replay label. The graph contains one example program and the timeline contains twenty-four events: its start, twenty web-port connection snapshots and three high-port connection snapshots. This is a generic example, not a recording of Age of Empires II.
3. Expect **zero findings** and **one neutral behavior note**. Open **Activity differs from the reference sample** under **Behavior notes**. Its score comes from the actual unchanged trained model, using a complete sixteen-event context. The model compares event patterns with an enterprise reference sample; normal games and other online apps can differ from that sample.
4. Read the note's limitations. The score is surprise in nats, not a malware probability, and does not establish a threat. Big Brother has not checked the server's reputation or connection contents. No findings does not establish safety.
5. Click an event-ID citation to open the exact recorded connection. If you open **Findings**, its empty view offers **View behavior notes** to return to the separate note.
6. Choose **Export** or **Export report** and save the JSON locally. It contains separate `incidents` and `behavior_notes` lists, the reference assessment, evidence IDs, model version and replay notice. Review these before sharing.

The [overview GIF](media/overview.gif) follows the Investigation graph and its two rule findings. The [evidence GIF](media/evidence.gif) opens the Online connections behavior note, follows a citation to its recorded event, exports a local report and returns to saved sessions. Both GIFs were captured from the actual v1.1.0 desktop app using fabricated replays.

Close the window and reopen it from the tray's **Show dashboard** action. Inspect retained sessions under **Sessions**; they also persist across a normal app restart. Use **Stop collection and exit** to close the app. This does not stop any separately installed Sysmon service.

The Windows GUI checks cover all three replay workflows, citation navigation, export, tray behaviour and restart retention. See [source GUI results](../artifacts/gui-smoke.json) and [packaged GUI results](../artifacts/packaged-gui-smoke.json) for the recorded runs. These checks verify application behaviour, not malware-detection accuracy.
