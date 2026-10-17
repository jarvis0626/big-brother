# Start using Big Brother

Big Brother helps you see what a Windows program is doing: which helper programs it starts, its recorded connections, and events that deserve a closer look. Your investigation stays on your computer unless you choose to share a report.

## Install or run

Download from the [v1.1.0 release](https://github.com/jarvis0626/big-brother/releases/tag/v1.1.0). Sign in to a GitHub account with access to this private repository.

- **Installer, recommended:** open `Big-Brother-1.1.0-x64-nsis.exe`, follow the setup steps, then open Big Brother from the Start menu.
- **Portable:** put `Big-Brother-1.1.0-x64-portable.exe` in a writable folder and open it. It keeps your history in `BigBrother-data` beside the executable. Keep that folder if you move the app.
- **Both together:** download `Big-Brother-1.1.0-Windows-x64.zip`, extract it, then choose either `Installer` or `Portable`. You only need to use one.

These are Windows 11, 64-bit builds. Python, Node, Docker, an API key and a paid subscription are not required. The files are unsigned, so Windows may display an unknown-publisher message; the release includes checksums for verifying downloaded files. Do not disable Windows security settings.

## Try the sample first

1. Open Big Brother and choose **Explore a replay**.
2. Select **Investigation**, then **Open replay**.
3. Look at the connected boxes. Each is a program; the lines show which program started another.
4. Open **Findings** and choose a finding. Read the observed facts and possible explanations.
5. Click an event reference to see the exact recorded event behind the explanation.

This is clearly marked sample data. Opening it never runs the programs described by the sample. GIFs in the README show this same workflow.

Next, choose **Explore a replay → Online connections → Open replay**. This fabricated example shows a model comparison under **Behavior notes**. Open the note and click its event references to see the categories that caused it. It does not contact a server or establish that a real game or server is safe.

## Watch a program

Use **Watch a process** to choose a program that is already open. Big Brother follows it and any observed helper programs. Activity before you started watching may be missing.

Use **Select executable** to choose an `.exe` file. Selecting it does not start it. **Launch and watch** starts the chosen file and observes it.

The activity timeline lets you search and inspect recorded events. Two parts of the app help you review them:

- **Behavior notes** are neutral comparisons with the model's reference sample. Games, browsers and online services can naturally behave differently from that sample. A note is not included in the Findings count and does not rate a server's reputation.
- **Findings** explain observed patterns identified by transparent rules. Open one to read the supporting facts, possible explanations and missing information.

Neither is a verdict that a program is malware. A quiet findings list is not proof of safety.

## When the app is waiting for more activity

The model needs **16 earlier supported events plus one new event** before comparing a sequence. Program starts and exits, DNS records and eligible connections count; other timeline events may not. While it is waiting, there is no reference score or behavior note. You can still inspect the timeline and any rule findings.

TCP connection attempts and closing connections stay in the timeline. Only established TCP connection snapshots enter the model comparison, so an attempted connection is not treated as a completed connection. Connection contents and server reputation are not checked.

## Save, stop and return later

- **Export** saves a local JSON report containing the current investigation. It can contain private paths, commands or destinations; review it before sharing.
- **Sessions** opens saved investigations. **Settings** controls how long history stays and the amount of evidence retained.
- **Pause analysis** stops new scoring while collection continues. **Stop session** stops this app's observation of that session; it does not close the watched program.
- Closing the window normally hides Big Brother in the system tray. Use **Stop collection and exit** from its menu to quit completely.

When you first open an older session in v1.1.0, the app refreshes its notes and findings using the same saved evidence. A paused session stays paused after that initial refresh.

## Other features and limits

**Import recording** opens a compatible normalized JSON recording as data. It never executes commands from the recording. **Settings → Telemetry coverage** explains which event types are available or missing.

Basic process and connection observation works without extra services. Broader file, Registry and DNS records require an already configured Microsoft Sysmon installation and suitable logging settings. Big Brother does not install or change Sysmon automatically; advanced setup is in [Windows setup](windows-setup.md).

Big Brother does not block programs, quarantine files or remove threats. The shipped model compares event sequences with an enterprise reference sample, and its malware-detection accuracy has not been established. Its weights and threshold are unchanged in v1.1.0. Research results and the separate static-file classifier are described in [the model card](model-card.md) and [static research report](static-pe-experiment.md); the static classifier is not part of this app's executable scanning. [The dataset audit](benign-data-audit.md) explains why a newly inspected Windows dataset was excluded from training.
