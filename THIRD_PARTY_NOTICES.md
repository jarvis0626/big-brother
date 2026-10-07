# Third-party notices

The original Big Brother source and eye vector are MIT licensed (see LICENSE). This is a source-level dependency review; authoritative installed licences are retained in the dependency distributions and Electron notices. Release packages retain Chromium/Electron licence files. Public training telemetry is **not bundled** in packages.

| Dependency | Purpose | Upstream licence/source |
|---|---|---|
| Electron | Desktop shell | MIT; Chromium includes BSD and other component licences; `LICENSE.electron.txt` and `LICENSES.chromium.html` in release |
| React / React DOM | Interface | MIT, https://github.com/facebook/react |
| @xyflow/react | Observed process graph | MIT, https://github.com/xyflow/xyflow |
| lucide-react | Interface icons | ISC, https://github.com/lucide-icons/lucide |
| psutil | Process snapshots | BSD-3-Clause, https://github.com/giampaolo/psutil |
| NumPy | Numeric utilities, if imported by runtime | BSD-3-Clause plus distributed numerical-library notices, https://numpy.org |
| Python | Frozen interpreter | PSF-2.0 and included component notices, https://docs.python.org/3/license.html |
| PyInstaller | Build/frozen loader | GPL-2.0-or-later with bootloader distribution exception; https://pyinstaller.org/en/stable/license.html |
| Pillow | Icon build tool; not runtime | HPND/PIL licence, https://github.com/python-pillow/Pillow |
| TypeScript, Vite, electron-builder, Playwright | Development tools | Apache-2.0 (TypeScript/Playwright), MIT (Vite/electron-builder) |
| PyTorch, scikit-learn | Training only | BSD-style licences; not packaged |

OpTC data provenance, source licence/public-domain statement, samples and exclusions are recorded in docs/dataset-card.md and training/dataset-manifest.json. Model weights trained by this project are described in docs/model-card.md. No third-party pretrained weights are required.

Sysmon is not bundled. Microsoft licence acceptance is required in its explicit setup workflow. Curated knowledge contains original summaries and source links, not copied full articles. MITRE ATT&CK attribution and Microsoft source references accompany the knowledge corpus.
