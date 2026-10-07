# Windows telemetry setup

Big Brother runs without an administrator account in reduced process-polling mode. No additional runtime, paid API, or service installation is necessary for replay, graph reconstruction, local scoring, retained history or reports.

## Optional richer collection with Sysmon

Sysmon is a Microsoft Sysinternals service **and kernel driver**. Installing it requires administrator privileges and acceptance of Microsoft's licence. It continues to collect events when Big Brother is paused, stopped or closed. Big Brother never installs, updates, reconfigures or removes it automatically.

Official download, capabilities and current requirements: [Microsoft Sysmon documentation](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon). Read the linked licence before installation. Obtain Sysmon only from Microsoft. It is not redistributed with Big Brother.

If you already have a managed Sysmon installation, ask your administrator about its logging policy. Do not replace that configuration.

To set up a personal installation explicitly:

1. Download and extract the official Sysmon ZIP into a directory you choose.
2. Review `scripts/sysmon-config.xml`. This example records process starts/stops, connection metadata, DNS, selected temporary-file creates and selected startup Registry changes. It does not record all file activity. Recording commands and paths may expose sensitive information.
3. In an administrator PowerShell, check the current schema with `Sysmon64.exe -s`. Adjust the example schema version to the version supported by your downloaded release, if needed.
4. Explicitly run `Sysmon64.exe -i "D:\Projects\Big Brother\scripts\sysmon-config.xml"`. Sysmon displays its licence prompt; accept only after reviewing it. This installs its privileged service and driver.
5. Reopen Big Brother. Settings/coverage show whether the Event Log is readable. Event Log access depends on local permissions. If denied, arrange narrowly scoped Event Log Reader permission with your administrator; do not grant the renderer administrator rights.
6. Verify enabled event types in Event Viewer → Applications and Services Logs → Microsoft → Windows → Sysmon → Operational. A readable channel does not prove that each event type is enabled. Big Brother labels policy-dependent coverage and gaps.

To stop or remove Sysmon, use Microsoft's documented controls explicitly, such as `Sysmon64.exe -u`, as administrator. Stopping Big Brother stops only its own collector.

## Running the packages

- Installer: `release/Big-Brother-0.1.0-x64-nsis.exe` installs per user and creates shortcuts. No administrator privilege is requested by the app.
- Portable launcher: `release/Big-Brother-0.1.0-x64-portable.exe` writes `BigBrother-data` beside itself. Put it in a writable folder. The extracted application is temporary; its retained data stays alongside the launcher.
- Extracted folder: `release/win-unpacked/Big Brother.exe` is usable independently if all adjacent files remain present. It stores history under the user's application-data directory.

These packages are unsigned. The build does not claim a verified publisher or a signing certificate.

Selecting an executable does not execute it. Only **Launch and watch** starts the selected program. Closing the window hides it in the system tray. Use the tray or application menu's **Stop collection and exit** to stop the application. Separately installed Sysmon continues running.
