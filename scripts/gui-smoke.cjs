'use strict';
// Real Electron Windows integration smoke; all data goes to a dedicated test directory.
const { _electron: electron } = require('playwright');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const root = path.resolve(__dirname, '..');
const output = path.join(root, 'artifacts');
const dataDir = path.join(root, '.cache', 'gui-smoke-' + Date.now());
process.env.ELECTRON_CACHE ||= path.join(root, '.cache', 'electron');
process.env.ELECTRON_BUILDER_CACHE ||= path.join(root, '.cache', 'electron-builder');
fs.mkdirSync(output, { recursive: true });
fs.mkdirSync(dataDir, { recursive: true });
const executable = process.env.BB_SMOKE_EXE || require('electron');
const tempDir = path.join(root, '.cache', 'temp');
fs.mkdirSync(tempDir, { recursive: true });
const env = { ...process.env, BB_DATA_DIR: dataDir, TEMP: tempDir, TMP: tempDir };
delete env.ELECTRON_RUN_AS_NODE;
delete env.BB_DEV;
const args = process.env.BB_SMOKE_EXE ? [] : [root];
const pageErrors = [];
const results = { platform: process.platform, executable, checks: [], started_at: new Date().toISOString() };
let app;

async function record(name, fn) {
  await fn();
  results.checks.push({ name, status: 'passed' });
  console.log('PASS ' + name);
}

async function getState(page, sessionId) {
  return page.evaluate(id => window.bigBrother.invoke('state', id ? { session_id: id } : {}), sessionId);
}

function observeErrors(page) {
  page.on('pageerror', error => pageErrors.push(String(error.message)));
}

async function openReplay(page, scenario) {
  const previousSessionId = (await getState(page)).session?.id;
  await page.getByRole('button', { name: /Explore a replay/ }).click();
  const dialog = page.getByRole('dialog', { name: 'Open a replay' });
  const scenarioName = scenario === 'ordinary' ? /^Ordinary activity/ : scenario === 'network' ? /^Online connections/ : /^Investigation/;
  await dialog.getByRole('button', { name: scenarioName }).click();
  await dialog.getByRole('button', { name: 'Open replay', exact: true }).click();
  await dialog.waitFor({ state: 'hidden' });
  await page.locator('.replay-notice').waitFor();
  await page.waitForFunction(previous => {
    const selected = document.querySelector('.session-select-wrap select')?.value;
    return selected && selected !== previous && document.querySelectorAll('.process-node').length >= 1;
  }, previousSessionId);
}

async function main() {
  app = await electron.launch({ executablePath: executable, args, env, timeout: 60000 });
  let page = await app.firstWindow({ timeout: 30000 });
  observeErrors(page);
  await page.waitForFunction(() => !!window.bigBrother, { timeout: 30000 });

  await record('Sandboxed renderer, context isolation and denied Node access', async () => {
    const prefs = await app.evaluate(({ BrowserWindow }) => BrowserWindow.getAllWindows()[0].webContents.getLastWebPreferences());
    assert.equal(prefs.sandbox, true);
    assert.equal(prefs.contextIsolation, true);
    assert.equal(prefs.nodeIntegration, false);
    assert.equal(await page.evaluate(() => typeof window.require), 'undefined');
    assert.equal(await page.evaluate(() => typeof window.process), 'undefined');
  });

  await record('Actual active trained model and readable collector state', async () => {
    const state = await getState(page);
    assert(state.model?.version && !/missing|unavailable|error/i.test(state.model.status), JSON.stringify(state.model));
    assert(Array.isArray(state.coverage));
    assert(state.collector?.backend);
    results.model = state.model;
    results.collector = state.collector;
    await page.getByRole('heading', { name: 'Activity overview', exact: true }).waitFor();
    await page.waitForFunction(() => !document.querySelector('.graph-loading'));
    assert.equal(await page.locator('.error-banner').count(), 0);
  });

  await record('Unknown renderer methods and injected parameters are rejected', async () => {
    const rejected = await page.evaluate(async () => {
      const checks = [
        ['launch', { path: 'C:\\Windows\\System32\\cmd.exe' }],
        ['import_recording', { path: 'C:\\Windows\\System32\\cmd.exe' }],
        ['watch', { pid: 12, command: 'execute' }],
        ['settings', { remote_key: 'unsafe' }],
      ];
      let count = 0;
      for (const [method, params] of checks) {
        try { await window.bigBrother.invoke(method, params); } catch { count++; }
      }
      return count;
    });
    assert.equal(rejected, 4);
  });

  await record('Executable selection does not execute a program', async () => {
    const before = await getState(page);
    await app.evaluate(({ dialog }, filePath) => {
      dialog.showOpenDialog = async () => ({ canceled: false, filePaths: [filePath] });
    }, process.execPath);
    await page.getByRole('button', { name: 'Select executable', exact: true }).click();
    const dialog = page.getByRole('dialog', { name: 'Launch and watch' });
    await dialog.waitFor();
    assert(await dialog.getByText(process.execPath, { exact: true }).isVisible());
    assert(await dialog.getByRole('button', { name: 'Launch and watch', exact: true }).isVisible());
    const after = await getState(page);
    assert.equal(after.sessions.length, before.sessions.length, 'Selecting a file must not create a launched session');
    await dialog.getByRole('button', { name: 'Close dialog', exact: true }).click();
  });

  let sessionId;
  let modelNote;
  let ruleFinding;
  let networkSessionId;
  let replayName;
  await record('Short investigation replay retains two rule findings and explains missing model context', async () => {
    await openReplay(page, 'investigation');
    const state = await getState(page);
    assert(state.session && /replay/i.test(state.session.mode));
    assert(state.events.length >= 6);
    assert(state.processes.length >= 3);
    assert.equal(state.incidents.length, 2, 'Replay must retain its two transparent rule findings');
    assert.equal(state.behavior_notes.length, 0, 'A short replay must not produce a model note without 16 preceding supported events');
    assert.equal(state.model_assessment.status, 'insufficient_context');
    const ids = new Set(state.events.map(e => e.id));
    assert(state.incidents.every(item => item.score_kind === 'rule_reference'));
    ruleFinding = state.incidents[0];
    for (const incident of state.incidents) {
      for (const fact of incident.explanation.observed) {
        assert(fact.event_ids.length > 0);
        for (const id of fact.event_ids) assert(ids.has(id));
      }
    }
    sessionId = state.session.id;
    replayName = state.session.name;
    results.replay = { session_id: sessionId, events: state.events.length, processes: state.processes.length, incidents: state.incidents.length, behavior_notes: state.behavior_notes.length };
    assert.equal(await page.locator('.finding-choice').count(), 2);
    assert.equal(await page.locator('.metric-card').filter({ hasText: 'Findings to review' }).locator('strong').innerText(), '2');
    assert(/Normal games/.test(await page.locator('.behavior-context').innerText()));
    assert(/reputation and connection contents are not checked/.test(await page.locator('.behavior-context').innerText()));
    assert(/Waiting for more supported activity/.test(await page.locator('.behavior-context').innerText()));
    assert.equal(await page.locator('.process-node').count(), state.processes.length);
    assert(await page.locator('.replay-notice').isVisible());
    assert(/fabricated/i.test(await page.locator('.replay-notice').innerText()));
    await page.screenshot({ path: path.join(output, 'dashboard.png'), fullPage: true });
  });

  await record('Rule finding citations navigate to exact evidence and Findings excludes model notes', async () => {
    const eventId = ruleFinding.explanation.observed[0].event_ids[0];
    // A citation must escape existing search filters rather than hide its own evidence.
    await page.getByLabel('Search evidence', { exact: true }).fill('no-matching-evidence-123456');
    await page.getByTitle('Show event ' + eventId, { exact: true }).first().click();
    await page.getByRole('heading', { name: 'Event details', exact: true }).waitFor();
    assert.equal(await page.locator('.event-selected').getAttribute('data-event-id'), eventId);
    assert((await page.locator('.event-detail').innerText()).includes(eventId));
    assert(/cited events/.test(await page.locator('.filter-notice').innerText()));
    await page.getByRole('button', { name: 'Close event details', exact: true }).click();
    await page.locator('.filter-notice').getByRole('button', { name: /Clear filter/ }).click();
    const navigation = page.getByRole('navigation', { name: 'Main navigation' });
    await navigation.getByRole('button', { name: /^Findings/ }).click();
    assert.equal(await page.locator('.finding-summary').count(), 2);
    await page.locator('.finding-summary').filter({ hasText: ruleFinding.title }).click();
    assert((await page.locator('.finding-expanded').innerText()).includes(ruleFinding.model_version));
    await page.getByRole('button', { name: 'View all evidence', exact: true }).click();
    await page.getByRole('heading', { name: 'Activity overview', exact: true }).waitFor();
    assert.equal(await page.locator('.event-row').count(), ruleFinding.event_ids.length);
    await page.locator('.filter-notice').getByRole('button', { name: /Clear filter/ }).click();
  });

  await record('Online connections replay exposes a real model score as a neutral, evidence-cited behavior note', async () => {
    await openReplay(page, 'network');
    const state = await getState(page);
    networkSessionId = state.session.id;
    assert.equal(state.incidents.length, 0);
    assert.equal(state.behavior_notes.length, 1);
    assert.equal(state.model_assessment.status, 'reference_only');
    modelNote = state.behavior_notes.find(note => Number.isFinite(note.score) && note.model_version === state.model.version);
    assert(modelNote, 'The unchanged trained model must supply the note score');
    assert.equal(modelNote.classification, 'reference_note');
    assert.equal(modelNote.severity, 'info');
    const ids = new Set(state.events.map(event => event.id));
    for (const fact of modelNote.explanation.observed) {
      assert(fact.event_ids.length > 0);
      for (const id of fact.event_ids) assert(ids.has(id));
    }
    await page.locator('.behavior-choice').filter({ hasText: modelNote.title }).click();
    await page.waitForFunction(version => document.querySelector('.behavior-detail .score-card code')?.textContent === version, state.model.version);
    assert.equal(await page.locator('.finding-choice').count(), 0);
    assert.equal(await page.locator('.metric-card').filter({ hasText: 'Findings to review' }).locator('strong').innerText(), '0');
    assert(!(await page.locator('.behavior-detail .badge').getAttribute('class')).includes('badge-high'));
    await page.getByRole('navigation', { name: 'Main navigation' }).getByRole('button', { name: /^Findings/ }).click();
    assert.equal(await page.locator('.finding-summary').count(), 0);
    await page.getByRole('button', { name: 'View behavior notes', exact: true }).click();
    await page.locator('.behavior-detail').waitFor();
    const eventId = modelNote.explanation.observed[0].event_ids[0];
    await page.getByLabel('Search evidence', { exact: true }).fill('no-matching-evidence-123456');
    await page.getByTitle('Show event ' + eventId, { exact: true }).first().click();
    await page.getByRole('heading', { name: 'Event details', exact: true }).waitFor();
    assert.equal(await page.locator('.event-selected').getAttribute('data-event-id'), eventId);
    assert((await page.locator('.event-detail').innerText()).includes(eventId));
    await page.getByRole('button', { name: 'Close event details', exact: true }).click();
    await page.locator('.filter-notice').getByRole('button', { name: /Clear filter/ }).click();
    results.network_replay = { session_id: networkSessionId, events: state.events.length, incidents: 0, behavior_notes: 1, model_score: modelNote.score };
    await page.screenshot({ path: path.join(output, 'network-behavior-note.png'), fullPage: true });
  });

  await record('Report export through the UI and native save dialog', async () => {
    const reportPath = path.join(dataDir, 'report.json');
    await app.evaluate(({ dialog }, filePath) => {
      dialog.showSaveDialog = async () => ({ canceled: false, filePath });
    }, reportPath);
    await page.locator('.session-controls').getByRole('button', { name: 'Export', exact: true }).click();
    await page.waitForFunction(() => document.querySelector('.toast')?.textContent.includes('Report exported'));
    const report = JSON.parse(fs.readFileSync(reportPath, 'utf8'));
    assert(JSON.stringify(report).includes(networkSessionId));
    assert.equal(report.incidents.length, 0);
    assert.equal(report.behavior_notes.length, 1);
    assert.equal(report.behavior_notes[0].classification, 'reference_note');
    results.report_path = reportPath;
  });

  await record('UI saves retention and bounded resource settings, and discloses coverage', async () => {
    await page.getByRole('button', { name: 'Settings', exact: true }).click();
    await page.getByLabel('Retention days', { exact: true }).fill('9');
    await page.getByLabel('Maximum retained events', { exact: true }).fill('18000');
    await page.getByLabel('Polling interval seconds', { exact: true }).fill('1.5');
    await page.getByLabel('Ingestion queue limit', { exact: true }).fill('4096');
    await page.getByLabel('Concurrent observation limit', { exact: true }).fill('20');
    await page.getByRole('button', { name: 'Save settings', exact: true }).click();
    await page.getByRole('button', { name: 'Settings saved', exact: true }).waitFor();
    const state = await getState(page);
    assert.equal(state.settings.retention_days, 9);
    assert.equal(state.settings.max_events, 18000);
    assert.equal(state.settings.poll_interval, 1.5);
    assert.equal(state.settings.max_queue, 4096);
    assert.equal(state.settings.max_sessions, 20);
    const unavailableBadges = page.locator('.coverage-row .badge').filter({ hasText: 'Unavailable' });
    for (let i = 0; i < await unavailableBadges.count(); i++) {
      assert(!(await unavailableBadges.nth(i).getAttribute('class')).includes('badge-live'));
    }
    assert((await page.locator('.model-details').innerText()).includes(state.model.version));
    assert(/privileged service and driver/.test(await page.locator('.coverage-setup').innerText()));
  });

  await record('Closing hides to tray and dashboard can reopen', async () => {
    const hidden = await app.evaluate(({ BrowserWindow }) => {
      const w = BrowserWindow.getAllWindows()[0];
      w.close();
      return !w.isVisible() && !w.isDestroyed();
    });
    assert.equal(hidden, true);
    await app.evaluate(({ BrowserWindow }) => BrowserWindow.getAllWindows()[0].show());
    assert.equal(await app.evaluate(({ BrowserWindow }) => BrowserWindow.getAllWindows()[0].isVisible()), true);
  });

  await record('Process picker searches and watches a benign running process', async () => {
    const processes = await page.evaluate(() => window.bigBrother.invoke('list_processes'));
    const list = Array.isArray(processes) ? processes : processes.processes;
    assert(list.some(p => p.pid === process.pid));
    await page.getByRole('button', { name: 'Watch a process', exact: true }).click();
    const dialog = page.getByRole('dialog', { name: 'Watch a process' });
    await dialog.getByLabel('Search running processes', { exact: true }).fill(String(process.pid));
    const row = dialog.locator('.process-picker-row').filter({ has: page.getByText(String(process.pid), { exact: true }) });
    await row.click();
    await dialog.getByRole('button', { name: 'Watch selected process', exact: true }).click();
    await dialog.waitFor({ state: 'hidden' });
    await page.locator('.ancestry-notice').waitFor();
    const state = await getState(page);
    assert.equal(state.session.ancestry_complete, false);
    assert(state.processes.some(p => p.pid === process.pid));
    assert(/Earlier ancestry and activity may be incomplete/.test(await page.locator('.ancestry-notice').innerText()));
    await page.getByRole('button', { name: 'Pause analysis', exact: true }).click();
    await page.getByRole('button', { name: 'Resume analysis', exact: true }).waitFor();
    assert.equal((await getState(page)).session.status, 'paused');
    await page.getByRole('button', { name: 'Resume analysis', exact: true }).click();
    await page.getByRole('button', { name: 'Pause analysis', exact: true }).waitFor();
    await page.getByRole('button', { name: 'Stop session', exact: true }).click();
    await page.waitForFunction(async () => (await window.bigBrother.invoke('state')).session.status === 'stopped');
    await page.evaluate(() => window.bigBrother.invoke('stop'));
  });

  await record('Ordinary replay is explicitly fabricated and available through UI', async () => {
    await openReplay(page, 'ordinary');
    const state = await getState(page);
    assert.equal(state.session.mode, 'replay');
    assert(state.events.every(e => e.source.includes('replay')));
    assert(await page.locator('.replay-notice').isVisible());
    results.ordinary_replay = { session_id: state.session.id, events: state.events.length, incidents: state.incidents.length };
  });

  let importedSessionId;
  const publicRecordingPath = process.env.BB_SMOKE_RECORDING || path.join(root, 'training', 'data', 'v2', 'recordings', 'otrf-a28dbf708685a80e.json');
  if (!fs.existsSync(publicRecordingPath)) throw new Error('The real normalized OTRF capture is needed for import UI validation: ' + publicRecordingPath);
  await record('Native dialog imports a real inert public recording with source provenance and capture coverage', async () => {
    const before = await getState(page);
    await app.evaluate(({ dialog }) => { dialog.showOpenDialog = async () => ({ canceled: true, filePaths: [] }); });
    await page.getByRole('button', { name: 'Import recording', exact: true }).click();
    await page.waitForFunction(() => !document.querySelector('.primary-actions button:disabled'));
    assert.equal((await getState(page)).sessions.length, before.sessions.length, 'Cancel must preserve sessions');
    await app.evaluate(({ dialog }, filePath) => {
      dialog.showOpenDialog = async () => ({ canceled: false, filePaths: [filePath] });
    }, publicRecordingPath);
    await page.getByRole('button', { name: 'Import recording', exact: true }).click();
    await page.locator('.recording-notice').waitFor();
    await page.waitForFunction(() => document.querySelectorAll('.process-node').length === 8);
    const state = await getState(page);
    assert.equal(state.session.mode, 'recording');
    assert.equal(state.session.status, 'recording');
    assert.equal(state.events.length, 83);
    assert.equal(state.processes.length, 8);
    assert(state.events.every(event => event.source.startsWith('recording:') && !event.details?.fabricated));
    assert.equal(state.recording.provenance.dataset, 'OTRF Security-Datasets');
    assert.equal(state.recording.provenance.revision, 'd9d40ef123d2c87d5d3df28c96bcab4f0faccc87');
    assert.equal(state.recording.imported_events, 83);
    assert(state.recording.observed_kinds.includes('process_access'));
    assert(state.coverage.every(item => item.backend === 'recording'));
    assert.equal(state.collector.status, 'idle', 'Recording import must not activate live collection');
    const notice = await page.locator('.recording-notice').innerText();
    assert(notice.includes('OTRF Security-Datasets'));
    assert(notice.includes(state.recording.provenance.revision));
    assert(notice.includes('Recorded adversary emulation'));
    assert(/never executed/.test(notice));
    assert(/partial capture/.test(await page.locator('.ancestry-notice').innerText()));
    assert.equal(await page.locator('.replay-notice').count(), 0);
    assert.equal(await page.getByRole('button', { name: 'Pause analysis', exact: true }).count(), 0);
    assert.equal(await page.getByRole('button', { name: 'Stop session', exact: true }).count(), 0);
    assert(/Imported recording/.test(await page.locator('.session-toolbar .badge').innerText()));
    const recordingIds = new Set(state.events.map(event => event.id));
    for (const incident of state.incidents) {
      for (const fact of incident.explanation.observed) {
        assert(fact.event_ids.length > 0);
        for (const id of fact.event_ids) assert(recordingIds.has(id));
      }
    }
    const accessEvent = state.events.find(event => event.kind === 'process_access');
    assert(accessEvent, 'The actual capture must preserve process-access evidence');
    await page.locator('[data-event-id="' + accessEvent.id + '"]').click();
    await page.getByRole('heading', { name: 'Event details', exact: true }).waitFor();
    assert((await page.locator('.event-detail').innerText()).includes(accessEvent.id));
    await page.getByRole('button', { name: 'Close event details', exact: true }).click();
    importedSessionId = state.session.id;
    results.imported_recording = { source_dataset: state.recording.provenance.dataset,
      revision: state.recording.provenance.revision, events: state.events.length,
      processes: state.processes.length, observed_kinds: state.recording.observed_kinds,
      capture_mode: state.session.mode, collector_status: state.collector.status,
      model_status: state.model.status, model_version: state.model.version,
      scenario_label_is_metadata: true, recorded_commands_executed: false };
    const reportPath = path.join(dataDir, 'recording-report.json');
    await app.evaluate(({ dialog }, filePath) => {
      dialog.showSaveDialog = async () => ({ canceled: false, filePath });
    }, reportPath);
    await page.locator('.session-controls').getByRole('button', { name: 'Export', exact: true }).click();
    await page.waitForFunction(() => document.querySelector('.toast')?.textContent.includes('Report exported'));
    const report = JSON.parse(fs.readFileSync(reportPath, 'utf8'));
    assert.equal(report.session.mode, 'recording');
    assert.equal(report.recording.provenance.dataset, 'OTRF Security-Datasets');
    assert.equal(report.events.length, 83);
    await page.screenshot({ path: path.join(dataDir, 'imported-recording.png'), fullPage: true });
  });

  await record('Retained replay history persists across application restart', async () => {
    await app.close();
    app = await electron.launch({ executablePath: executable, args, env, timeout: 60000 });
    page = await app.firstWindow();
    observeErrors(page);
    await page.waitForFunction(() => !!window.bigBrother);
    const state = await getState(page, sessionId);
    assert(state.sessions.some(s => s.id === sessionId));
    assert(state.sessions.some(s => s.id === importedSessionId && s.mode === 'recording'));
    assert(state.events.length >= 6);
    await page.getByRole('navigation', { name: 'Main navigation' }).getByRole('button', { name: 'Sessions', exact: true }).click();
    await page.getByLabel('Search sessions', { exact: true }).fill(replayName);
    await page.locator('.session-name-button').filter({ hasText: replayName }).click();
    await page.locator('.replay-notice').waitFor();
    await page.waitForFunction(id => document.querySelector('.session-select-wrap select')?.value === id, sessionId);
    assert.equal(await page.locator('.event-row').count(), state.events.length);
  });

  await record('Imported source recording remains distinct in history after restart', async () => {
    await page.getByRole('navigation', { name: 'Main navigation' }).getByRole('button', { name: 'Sessions', exact: true }).click();
    await page.getByLabel('Search sessions', { exact: true }).fill('Lsass Memory Dump via Syscalls');
    const row = page.locator('.session-table-row').filter({ has: page.locator('.session-name-button').filter({ hasText: 'Lsass Memory Dump via Syscalls' }) });
    assert(/Imported recording/.test(await row.innerText()));
    assert(!/Live observation|Replay/.test(await row.innerText()));
    await row.locator('.session-name-button').click();
    await page.locator('.recording-notice').waitFor();
    await page.waitForFunction(id => document.querySelector('.session-select-wrap select')?.value === id, importedSessionId);
    assert.equal((await getState(page)).events.length, 83);
    assert.equal(await page.locator('.process-node').count(), 8);
  });

  await record('No uncaught renderer errors during the real UI workflow', async () => {
    assert.deepEqual(pageErrors, []);
    assert.equal(await page.locator('.error-banner').count(), 0);
    results.renderer_errors = pageErrors;
  });

  await app.close();
  app = null;
  results.status = 'passed';
  results.finished_at = new Date().toISOString();
  fs.writeFileSync(path.join(output, process.env.BB_SMOKE_EXE ? 'packaged-gui-smoke.json' : 'gui-smoke.json'), JSON.stringify(results, null, 2));
  console.log('Electron integration checks passed; screenshot artifacts/dashboard.png');
}

main().catch(async error => {
  results.status = 'failed';
  results.error = String(error.stack || error);
  results.renderer_errors = pageErrors;
  fs.writeFileSync(path.join(output, 'gui-smoke-failure.json'), JSON.stringify(results, null, 2));
  if (app) await app.close().catch(() => {});
  console.error(error);
  process.exitCode = 1;
});
