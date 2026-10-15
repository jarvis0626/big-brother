# Start using Big Brother

Big Brother helps you see what a Windows program is doing: which helper programs it starts, its recorded connections, and events that deserve a closer look. Your investigation stays on your computer unless you choose to share a report.

## Install or run

Download from the [v1.0.0 release](https://github.com/jarvis0626/big-brother/releases/tag/v1.0.0). Sign in to a GitHub account with access to this private repository.

- **Installer, recommended:** open `Big-Brother-1.0.0-x64-nsis.exe`, follow the setup steps, then open Big Brother from the Start menu.
- **Portable:** put `Big-Brother-1.0.0-x64-portable.exe` in a writable folder and open it. It keeps your history in `BigBrother-data` beside the executable. Keep that folder if you move the app.
- **Both together:** download `Big-Brother-1.0.0-Windows-x64.zip`, extract it, then choose either `Installer` or `Portable`. You only need to use one.

These are Windows 11, 64-bit builds. Python, Node, Docker, an API key and a paid subscription are not required. The files are unsigned, so Windows may display an unknown-publisher message; the release includes checksums for verifying downloaded files. Do not disable Windows security settings.

## Try the sample first

1. Open Big Brother and choose **Explore a replay**.
2. Select **Investigation**, then **Open replay**.
3. Look at the connected boxes. Each is a program; the lines show which program started another.
4. Open **Findings** and choose a finding. Read the observed facts and possible explanations.
5. Click an event reference to see the exact recorded event behind the explanation.

This is clearly marked sample data. Opening it never runs the programs described by the sample. GIFs in the README show this same workflow.

## Watch a program

Use **Watch a process** to choose a program that is already open. Big Brother follows it and any observed helper programs. Activity before you started watching may be missing.

Use **Select executable** to choose an `.exe` file. Selecting it does not start it. **Launch and watch** starts the chosen file and observes it.

The activity timeline lets you search and inspect recorded events. **Findings** highlights unusual patterns and separately explains reference rules. A finding suggests something to investigate; it is not a verdict that a program is malware. A quiet findings list is not proof of safety.

## Save, stop and return later

- **Export** saves a local JSON report containing the current investigation. It can contain private paths, commands or destinations; review it before sharing.
- **Sessions** opens saved investigations. **Settings** controls how long history stays and the amount of evidence retained.
- **Pause analysis** stops new scoring while collection continues. **Stop session** stops this app's observation of that session; it does not close the watched program.
- Closing the window normally hides Big Brother in the system tray. Use **Stop collection and exit** from its menu to quit completely.

## Other features and limits

**Import recording** opens a compatible normalized JSON recording as data. It never executes commands from the recording. **Settings → Telemetry coverage** explains which event types are available or missing.

Basic process and connection observation works without extra services. Broader file, Registry and DNS records require an already configured Microsoft Sysmon installation and suitable logging settings. Big Brother does not install or change Sysmon automatically; advanced setup is in [Windows setup](windows-setup.md).

Big Brother does not block programs, quarantine files or remove threats. The shipped model detects unusual event sequences, and its malware-detection accuracy has not been established. Research results and the separate static-file classifier are described in [the model card](model-card.md) and [static research report](static-pe-experiment.md); the static classifier is not part of this app's executable scanning.
