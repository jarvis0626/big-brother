'use strict';
const { app, BrowserWindow, Menu, Tray, dialog, ipcMain, shell, nativeImage } = require('electron');
const { spawn } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');
const readline = require('node:readline');
const { pathToFileURL } = require('node:url');
const { validateRequest, validateExternal, validId } = require('./security.cjs');

app.setName('Big Brother');
app.setAppUserModelId('org.bigbrother.desktop');
const root = path.join(__dirname, '..');
let mainWindow, tray, backend, selectedExecutable, quitting = false, ready = false;
let sequence = 0;
let closeToTray = true;
const pending = new Map();
const uiFile = path.join(root, 'dist', 'ui', 'index.html');
const dev = !app.isPackaged && process.env.BB_DEV === '1';
const trustedUrl = dev ? 'http://127.0.0.1:5173/' : pathToFileURL(uiFile).href;
const dataDir = process.env.BB_DATA_DIR || (process.env.PORTABLE_EXECUTABLE_DIR
  ? path.join(process.env.PORTABLE_EXECUTABLE_DIR, 'BigBrother-data') : app.getPath('userData'));
app.setPath('userData', dataDir);
if (!app.requestSingleInstanceLock()) app.quit();
app.on('second-instance', () => { if (mainWindow) { mainWindow.show(); mainWindow.focus(); } });

function trusted(event) {
  if (!mainWindow || event.sender !== mainWindow.webContents || event.senderFrame !== mainWindow.webContents.mainFrame) throw new Error('Untrusted caller');
  const frameUrl = event.senderFrame.url.split('#')[0];
  if (frameUrl !== trustedUrl) throw new Error('Untrusted page');
}
function rejectPending(reason) {
  for (const p of pending.values()) { clearTimeout(p.timer); p.reject(new Error(reason)); }
  pending.clear();
}
function rpc(method, params = {}) {
  return new Promise((resolve, reject) => {
    if (!backend || backend.exitCode !== null || backend.killed) return reject(new Error('Collector is disconnected. Restart Big Brother to reconnect.'));
    if (pending.size >= 64) return reject(new Error('Collector is busy. Try again shortly.'));
    const id = ++sequence;
    const timer = setTimeout(() => { pending.delete(id); reject(new Error('Collector did not respond in time')); }, 30000);
    pending.set(id, { resolve, reject, timer });
    backend.stdin.write(JSON.stringify({ id, method, params }) + '\n', 'utf8', (error) => {
      if (error && pending.has(id)) { clearTimeout(timer); pending.delete(id); reject(new Error('Collector connection failed')); }
    });
  });
}
function startBackend() {
  const resources = app.isPackaged ? path.join(process.resourcesPath, 'data') : path.join(root, 'resources');
  const executable = app.isPackaged ? path.join(process.resourcesPath, 'backend', 'big-brother-service.exe') : path.join(root, '.venv', 'Scripts', 'python.exe');
  const args = app.isPackaged ? [] : ['-u', '-m', 'backend.service'];
  args.push('--data-dir', dataDir, '--resources', resources);
  fs.mkdirSync(dataDir, { recursive: true });
  backend = spawn(executable, args, { cwd: app.isPackaged ? dataDir : root, windowsHide: true, shell: false, stdio: ['pipe', 'pipe', 'pipe'], env: { ...process.env, PYTHONIOENCODING: 'utf-8', PYTHONUNBUFFERED: '1' } });
  const lines = readline.createInterface({ input: backend.stdout });
  lines.on('line', (line) => {
    if (line.length > 32 * 1024 * 1024) return rejectPending('Collector response exceeds resource limit');
    let result; try { result = JSON.parse(line); } catch { return; }
    const p = pending.get(result.id); if (!p) return;
    pending.delete(result.id); clearTimeout(p.timer);
    if (result.error) p.reject(new Error(typeof result.error === 'string' ? result.error : result.error.message || 'Collector action failed'));
    else p.resolve(result.result);
  });
  backend.stderr.on('data', () => {}); // Telemetry may contain secrets; never forward it to renderer logs.
  backend.on('error', () => rejectPending('Unable to start the bundled collector'));
  backend.on('exit', () => { ready = false; rejectPending('Collector disconnected. Restart Big Brother to reconnect.'); });
  backend.stdin.on('error', () => rejectPending('Collector disconnected'));
}
function createWindow() {
  mainWindow = new BrowserWindow({ width: 1440, height: 940, minWidth: 1000, minHeight: 700,
    title: 'Big Brother', backgroundColor: '#101114', icon: path.join(root, 'assets', 'icon.ico'),
    webPreferences: { preload: path.join(__dirname, 'preload.cjs'), contextIsolation: true, sandbox: true, nodeIntegration: false, webSecurity: true, devTools: !app.isPackaged }
  });
  mainWindow.webContents.setWindowOpenHandler(() => ({ action: 'deny' }));
  mainWindow.webContents.on('will-navigate', (event, url) => { if (url !== trustedUrl) event.preventDefault(); });
  mainWindow.webContents.session.setPermissionRequestHandler((_wc, _permission, callback) => callback(false));
  mainWindow.webContents.session.setPermissionCheckHandler(() => false);
  if (process.argv.includes('--smoke-test')) {
    mainWindow.webContents.once('did-finish-load', async () => {
      try {
        const session = await rpc('replay', { scenario: 'investigation' });
        const state = await rpc('state', { session_id: session.id });
        const renderer = await mainWindow.webContents.executeJavaScript('({ title: document.title, nodeAvailable: typeof window.require !== "undefined", bridgeAvailable: !!window.bigBrother, text: document.body.innerText })');
        const modelFinding = state.incidents.some(i => typeof i.score === 'number' && i.model_version === state.model.version);
        const passed = renderer.title === 'Big Brother' && !renderer.nodeAvailable && renderer.bridgeAvailable && renderer.text.includes('Big Brother') && modelFinding && state.events.length === 13;
        const report = { passed, packaged: app.isPackaged, version: app.getVersion(), data_dir: dataDir, portable: !!process.env.PORTABLE_EXECUTABLE_DIR,
          resources_present: fs.existsSync(path.join(process.resourcesPath, 'backend', 'big-brother-service.exe')),
          model: { name: state.model.name, version: state.model.version, status: state.model.status },
          events: state.events.length, processes: state.processes.length, incidents: state.incidents.length, model_finding: modelFinding,
          sandbox: mainWindow.webContents.getLastWebPreferences().sandbox, node_available: renderer.nodeAvailable, title: renderer.title };
        await fs.promises.writeFile(path.join(dataDir, 'package-smoke.json'), JSON.stringify(report, null, 2));
      } catch (error) {
        await fs.promises.writeFile(path.join(dataDir, 'package-smoke.json'), JSON.stringify({ passed: false, error: String(error.message) }));
      } finally { await quitSafely(); }
    });
  }
  mainWindow.on('close', (event) => { if (!quitting) { event.preventDefault(); if (closeToTray) mainWindow.hide(); else quitSafely(); } });
  mainWindow.loadURL(trustedUrl);
  Menu.setApplicationMenu(Menu.buildFromTemplate([
    { label: 'Big Brother', submenu: [
      { label: 'Show window', click: () => mainWindow.show() },
      { label: 'Stop collection and exit', accelerator: 'Alt+F4', click: quitSafely }
    ] },
    { label: 'View', submenu: [{ role: 'reload' }, { role: 'resetZoom' }, { role: 'zoomIn' }, { role: 'zoomOut' }, { role: 'togglefullscreen' }] },
    { label: 'Help', submenu: [
      { label: 'Open telemetry setup files', click: () => shell.openPath(app.isPackaged ? path.join(process.resourcesPath, 'docs') : path.join(root, 'docs')) },
      { label: 'Microsoft Sysmon documentation', click: () => shell.openExternal('https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon') }
    ] }
  ]));
  tray = new Tray(nativeImage.createFromPath(path.join(root, 'assets', 'icon.ico')));
  tray.setToolTip('Big Brother — process observation');
  tray.setContextMenu(Menu.buildFromTemplate([
    { label: 'Big Brother', enabled: false },
    { label: 'Show dashboard', click: () => { mainWindow.show(); mainWindow.focus(); } },
    { type: 'separator' },
    { label: 'Stop app collection', click: () => rpc('stop').catch(() => {}) },
    { label: 'Stop collection and exit', click: quitSafely }
  ]));
  tray.on('double-click', () => { mainWindow.show(); mainWindow.focus(); });
}
async function quitSafely() {
  if (quitting) return; quitting = true;
  if (backend && !backend.killed) {
    const exited = new Promise(resolve => {
      if (backend.exitCode !== null) return resolve(true);
      backend.once('exit', () => resolve(true));
    });
    try { await Promise.race([rpc('shutdown'), new Promise((resolve) => setTimeout(resolve, 2000))]); } catch {}
    const graceful = await Promise.race([exited, new Promise(resolve => setTimeout(() => resolve(false), 5000))]);
    if (!graceful && backend.exitCode === null) backend.kill();
  }
  if (tray) tray.destroy();
  app.quit();
}
ipcMain.handle('bb:request', async (event, method, params) => {
  trusted(event); const result = await rpc(method, validateRequest(method, params));
  if (method === 'state' && result?.settings) closeToTray = result.settings.close_to_tray !== false;
  if (method === 'settings') closeToTray = result.close_to_tray !== false;
  return result;
});
ipcMain.handle('bb:select', async (event) => {
  trusted(event);
  const result = await dialog.showOpenDialog(mainWindow, { title: 'Select an executable to observe', filters: [{ name: 'Windows executable', extensions: ['exe'] }], properties: ['openFile'] });
  if (result.canceled || !result.filePaths[0]) return null;
  selectedExecutable = result.filePaths[0]; return { path: selectedExecutable };
});
ipcMain.handle('bb:launch-selected', async (event) => {
  trusted(event);
  if (!selectedExecutable || path.extname(selectedExecutable).toLowerCase() !== '.exe') throw new Error('Select a Windows executable first');
  const stat = await fs.promises.stat(selectedExecutable); if (!stat.isFile()) throw new Error('Selected executable is unavailable');
  return rpc('launch', { path: selectedExecutable });
});
ipcMain.handle('bb:import-recording', async (event, ...args) => {
  trusted(event);
  if (args.length) throw new Error('Recording import accepts no renderer parameters');
  const result = await dialog.showOpenDialog(mainWindow, {
    title: 'Import a normalized recording',
    filters: [{ name: 'Big Brother recording JSON', extensions: ['json'] }],
    properties: ['openFile']
  });
  if (result.canceled || !result.filePaths[0]) return null;
  const selected = result.filePaths[0];
  if (!path.isAbsolute(selected) || path.extname(selected).toLowerCase() !== '.json') throw new Error('Choose a normalized recording JSON file');
  const stat = await fs.promises.stat(selected);
  if (!stat.isFile() || stat.size > 32 * 1024 * 1024) throw new Error('Recording must be a JSON file no larger than 32 MiB');
  return rpc('import_recording', { path: selected });
});
ipcMain.handle('bb:export', async (event, sessionId) => {
  trusted(event); if (!validId(sessionId)) throw new Error('Invalid session');
  const result = await dialog.showSaveDialog(mainWindow, { title: 'Export investigation report', defaultPath: `Big-Brother-${sessionId}.json`, filters: [{ name: 'JSON report', extensions: ['json'] }] });
  if (result.canceled || !result.filePath) return { canceled: true };
  const report = await rpc('export', { session_id: sessionId });
  await fs.promises.writeFile(result.filePath, typeof report === 'string' ? report : JSON.stringify(report, null, 2), { encoding: 'utf8', mode: 0o600 });
  return { canceled: false, path: result.filePath };
});
ipcMain.handle('bb:documentation', (event, url) => { trusted(event); return shell.openExternal(validateExternal(url)); });
app.whenReady().then(() => { startBackend(); createWindow(); ready = true; });
app.on('before-quit', (event) => { if (!quitting && ready) { event.preventDefault(); quitSafely(); } });
app.on('window-all-closed', () => {});
app.on('activate', () => { if (mainWindow) mainWindow.show(); });
