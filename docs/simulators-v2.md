# Harmless Windows behavior simulators

Three real Windows executable programs exercise Big Brother's process and
connection collector. They contain no malware, and their findings do not measure
malware detection accuracy. Their source is
[`behavior_app.py`](../scripts/simulators/behavior_app.py).

| Executable in `release/simulators` | Actual bounded behavior |
| --- | --- |
| `BigBrotherOrdinarySimulator.exe` | Three owned scratch files, localhost resolution, and ordinary loopback echo connections for eight seconds. |
| `BigBrotherFanoutSimulator.exe` | Three trusted helper copies, 36 total owned scratch files, and loopback echo connections while the parent waits for its children. |
| `BigBrotherSurvivorSimulator.exe` | A trusted helper starts, the parent exits, and that helper continues loopback echo connections before exiting on its own. Eight owned scratch files are created. |

Each executable defaults to its scenario when selected and launched in Big
Brother's native executable dialog. The same compiled program is copied under
three descriptive filenames; the filename selects its default scenario. Each is
a self-contained PyInstaller executable, with no Python installation required.
They are unsigned. Their initial console identifies them as harmless tests.

All network targets are numeric loopback addresses. Each connection exchanges a
fixed harmless string. `localhost` resolution may use the hosts file or a cache;
it is not proof of an observed DNS request. Processes execute this same trusted
program directly with argument arrays and never invoke a shell. Files are small
plaintext examples within a newly generated `bb-simulator-<token>` directory.
No existing user file is opened, encrypted, or overwritten. No Registry changes,
startup persistence, credential access, external communication, service install,
or Defender changes occur.

## Build and watch a scenario

From a PowerShell prompt in the project directory:

```powershell
.venv\Scripts\python.exe scripts\simulators\build.py
```

In Big Brother, choose **Select executable**, select one of the three files in
`release\simulators`, and confirm **Launch and watch**. Inspect the actual process
graph and timeline. The ordinary scenario also makes network connections;
network activity alone is expected for many benign programs.

The surviving-child scenario should exercise the separately labeled transparent
rule about a child connecting after its parent ends. An anomaly-model finding is
possible in any scenario, because an enterprise training reference can rate a
known-benign local test as unusual. Scores are not malware probabilities.
Thresholds are not adjusted to force simulator alerts. A quiet finding list is
not evidence that an arbitrary executable is safe.

## Validate the production collector and trained model

```powershell
.venv\Scripts\python.exe -m pytest tests\test_simulators_v2.py -q --basetemp=.cache\simulator-unit-tests
.venv\Scripts\python.exe scripts\validate_simulators.py
```

The validator launches the actual compiled `.exe` files through the same
`Application.launch` production API used by the desktop bridge. It observes
native Windows process snapshots and live loopback TCP connections, invokes the
genuine currently active trained model, checks descendant attribution and
finding citations, and verifies the surviving-child reference rule. It never
injects events into these live sessions. Raw captured evidence is confined to a
disposable scratch SQLite database on D: and deleted after validation. The
committed report
[`simulator-validation-v2.json`](../artifacts/simulator-validation-v2.json)
contains aggregate experimental counts and model results, without command lines,
local evidence paths, process IDs, or raw telemetry.

Windows polling cannot collect the file operations or hostname queries as
events. The report distinguishes the files the program actually created from
the file events the collector observed. An already configured Sysmon channel
may provide extra evidence, but this test does not install or modify Sysmon and
does not claim configuration coverage. One-file bootloader processes appear in
the observed lineage. Very brief activity between polls can still be missed.

## Owned scratch files and cleanup

Manual runs leave only their bounded example files and trace records below
`release\simulators\simulator-runs` for inspection. These files are ignored by
Git. Build caches and one-file runtime extraction are under
`.cache\simulator-build` on D:. A run prints its exact directory and cleanup
token at startup. Cleanup requires both that generated directory and its
matching ownership marker:

```powershell
.\release\simulators\BigBrotherOrdinarySimulator.exe --clean-run "D:\Projects\Big Brother\release\simulators\simulator-runs\bb-simulator-<token>" --token <token>
```

Replace both `<token>` occurrences with the actual printed token. Cleanup
refuses a mismatched marker, any link or junction, or an unowned directory. The
automated validator waits for its own bounded helpers to exit and cleans only
the exact run it created. Pre-existing run directories and unrelated files are
preserved.

## Separate fabricated example

[`fabricated-persistence.json`](../scripts/simulators/fabricated-persistence.json)
illustrates a startup Registry event using explicitly fabricated telemetry. The
program never performs that operation. This file is documentation only; it is
not imported into live sessions, used for training, or counted as detection
accuracy. It exists to demonstrate the distinction between safe executable
workloads and a mocked attack-shaped event stream.
