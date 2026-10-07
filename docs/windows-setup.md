# Windows telemetry setup

Big Brother runs without an administrator account in reduced process-polling mode. No additional runtime, paid API, or service installation is necessary for replay, graph reconstruction, local scoring, retained history or reports.

## Optional richer collection with Sysmon

Sysmon is a Microsoft Sysinternals service **and kernel driver**. Installing it requires administrator privileges and acceptance of Microsoft's licence. It continues to collect events when Big Brother is paused, stopped or closed. Big Brother never installs, updates, reconfigures or removes it automatically.

Official download, capabilities and current requirements: [Microsoft Sysmon documentation](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon). Read the linked licence before installation. Obtain Sysmon only from Microsoft. It is not redistributed with Big Brother.

If you already have a managed Sysmon installation, ask your administrator about its logging policy. Do not replace that configuration.

To set up a personal installation explicitly:

1. Download and extract the official Sysmon ZIP into a directory you choose.
2. In Big Brother, choose **Help → Open telemetry setup files**. Packaged apps include `windows-setup.md` and `sysmon-config.xml` in that folder. Copy the example XML to a stable location before configuring Sysmon, especially when using the portable launcher, whose extracted files are temporary. Source checkouts instead use `scripts/sysmon-config.xml`. Review the XML: it records process starts/stops, connection metadata, DNS, selected temporary-file creates and selected startup Registry changes. It does not record all file activity. Recording commands and paths may expose sensitive information.
3. In an administrator PowerShell, change to the folder containing the downloaded `Sysmon64.exe`, and check the current schema with `.\Sysmon64.exe -s`. Adjust the example schema version to the version supported by your downloaded release, if needed.
4. Explicitly run `.\Sysmon64.exe -i "C:\path\you\chose\sysmon-config.xml"`, replacing the quoted path with the full path to your reviewed configuration. Sysmon displays its licence prompt; accept only after reviewing it. This installs its privileged service and driver.
5. Reopen Big Brother and start a watch. **Settings → Telemetry coverage** shows whether the Event Log is readable; before a watch begins, the channel may be labelled not checked yet. Event Log access depends on local permissions. If denied, arrange narrowly scoped Event Log Reader permission with your administrator; do not grant the renderer administrator rights.
6. Verify enabled event types in Event Viewer → Applications and Services Logs → Microsoft → Windows → Sysmon → Operational. A readable channel does not prove that each event type is enabled. Big Brother labels policy-dependent coverage and gaps.

To stop or remove Sysmon, use Microsoft's documented controls explicitly, such as `.\Sysmon64.exe -u` from its directory, as administrator. Stopping Big Brother stops only its own collector.

## Running the packages

- Installer: `release/Big-Brother-0.2.0-x64-nsis.exe` installs per user and creates shortcuts. No administrator privilege is requested by the app.
- Portable launcher: `release/Big-Brother-0.2.0-x64-portable.exe` writes `BigBrother-data` beside itself. Put it in a writable folder. The extracted application is temporary; its retained data stays alongside the launcher.
- Extracted folder: `release/win-unpacked/Big Brother.exe` is usable independently if all adjacent files remain present. It stores history under the user's application-data directory.

These packages are unsigned. The build does not claim a verified publisher or a signing certificate.

The v0.2 example XML also records remote-thread creation and access to `lsass.exe`, enabling separately labelled evidence references. It does not enable broad module-load recording. Validate the XML against the downloaded Sysmon schema before applying it. This configuration is shipped as an optional setup file and has not been installed or live-tested on the development machine.

Selecting an executable does not execute it. Only **Launch and watch** starts the selected program. Closing the window hides it in the system tray. Use the tray or application menu's **Stop collection and exit** to stop the application. Separately installed Sysmon continues running.

For a reproducible, harmless first investigation, follow the [five-minute replay demo](demo.md). Native process polling, replay, the real installer and portable launcher were tested on the development Windows machine. Live Sysmon ingestion was not validated here because the channel is not configured; readability and event coverage must be checked on the target computer.
