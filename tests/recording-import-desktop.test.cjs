'use strict';
// Exercise the actual main-process handler while preventing any executable launch.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { pathToFileURL } = require('node:url');

function harness({ canceled = false, filename = 'capture.json', size = 4096, isFile = true } = {}) {
  const project = path.resolve(__dirname, '..');
  const handlers = new Map();
  const picked = path.join(project, '.cache', 'recording-import-unit', filename);
  let dialogs = 0;
  const requests = [];
  const app = {
    setName() {}, setAppUserModelId() {}, setPath() {}, on() {}, quit() {},
    getPath: () => path.join(project, '.cache', 'recording-import-unit-data'),
    requestSingleInstanceLock: () => true,
    whenReady: () => ({ then() {} }),
  };
  const electron = { app, ipcMain: { handle: (name, fn) => handlers.set(name, fn) },
    dialog: { showOpenDialog: async (_window, options) => {
      dialogs++;
      assert.deepEqual(Array.from(options.filters[0].extensions), ['json']);
      assert.deepEqual(Array.from(options.properties), ['openFile']);
      return { canceled, filePaths: canceled ? [] : [picked] };
    } } };
  const context = vm.createContext({
    __dirname: path.join(project, 'desktop'),
    process: { env: {}, argv: [] },
    setTimeout, clearTimeout, Promise, console,
    require: name => {
      if (name === 'electron') return electron;
      if (name === 'node:child_process') return { spawn: () => { throw new Error('Recording import must never launch a program'); } };
      if (name === 'node:fs') return { promises: { stat: async target => {
        assert.equal(target, picked);
        return { size, isFile: () => isFile };
      } } };
      if (name === './security.cjs') return require('../desktop/security.cjs');
      return require(name);
    },
  });
  vm.runInContext(fs.readFileSync(path.join(project, 'desktop', 'main.cjs'), 'utf8'), context);
  const frame = { url: pathToFileURL(path.join(project, 'dist', 'ui', 'index.html')).href };
  const webContents = { mainFrame: frame };
  context.testWindow = { webContents };
  context.testBackend = { exitCode: null, killed: false, stdin: { write: (line, _encoding, callback) => {
    const request = JSON.parse(line);
    requests.push(request);
    vm.runInContext(`{ const item = pending.get(${request.id}); clearTimeout(item.timer); pending.delete(${request.id}); item.resolve({ id: 'session_imported' }); }`, context);
    callback();
  } } };
  vm.runInContext('mainWindow = testWindow; backend = testBackend;', context);
  return { invoke: handlers.get('bb:import-recording'), event: { sender: webContents, senderFrame: frame },
    requests, get dialogs() { return dialogs; } };
}

test('Only a trusted top-level page can import through the native picker', async () => {
  const h = harness();
  await assert.rejects(h.invoke({ ...h.event, senderFrame: { url: h.event.senderFrame.url } }), /Untrusted caller/);
  await assert.rejects(h.invoke({ ...h.event, sender: {} }), /Untrusted caller/);
  h.event.senderFrame.url = 'https://example.com/';
  await assert.rejects(h.invoke(h.event), /Untrusted page/);
  assert.equal(h.dialogs, 0);
  assert.equal(h.requests.length, 0);
});

test('Renderer arguments cannot supply an import path or executable payload', async () => {
  const h = harness();
  await assert.rejects(h.invoke(h.event, { path: 'C:\\Windows\\System32\\cmd.exe' }), /no renderer parameters/);
  await assert.rejects(h.invoke(h.event, undefined), /no renderer parameters/);
  assert.equal(h.dialogs, 0);
  assert.equal(h.requests.length, 0);
});

test('Cancel returns no session and issues no backend request', async () => {
  const h = harness({ canceled: true });
  assert.equal(await h.invoke(h.event), null);
  assert.equal(h.dialogs, 1);
  assert.equal(h.requests.length, 0);
});

test('Native JSON selection forwards only its path to private recording import', async () => {
  const h = harness();
  assert.equal((await h.invoke(h.event)).id, 'session_imported');
  assert.equal(h.requests.length, 1);
  assert.equal(h.requests[0].method, 'import_recording');
  assert.deepEqual(Object.keys(h.requests[0].params), ['path']);
  assert(h.requests[0].params.path.endsWith('capture.json'));
});

test('Picker results must be JSON regular files inside the 32MiB limit', async () => {
  for (const options of [{ filename: 'program.exe' }, { size: 32 * 1024 * 1024 + 1 }, { isFile: false }]) {
    const h = harness(options);
    await assert.rejects(h.invoke(h.event), /JSON file/);
    assert.equal(h.requests.length, 0);
  }
});
