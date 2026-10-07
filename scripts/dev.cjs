const { spawn } = require('node:child_process');
const path = require('node:path');
process.env.ELECTRON_CACHE = path.resolve('.cache/electron');
delete process.env.ELECTRON_RUN_AS_NODE;
const env = { ...process.env, BB_DEV: '1', ELECTRON_CACHE: path.resolve('.cache/electron'), ELECTRON_BUILDER_CACHE: path.resolve('.cache/electron-builder') };
const vite = spawn(process.execPath, [path.resolve('node_modules/vite/bin/vite.js')], { env, stdio: 'inherit' });
let electron;
async function launch() {
  for (let i = 0; i < 60; i++) {
    try { if ((await fetch('http://127.0.0.1:5173')).ok) break; } catch {}
    await new Promise(r => setTimeout(r, 500));
  }
  const cleanEnv = { ...env }; delete cleanEnv.ELECTRON_RUN_AS_NODE;
  electron = spawn(require('electron'), ['.'], { env: cleanEnv, stdio: 'inherit' });
  electron.on('exit', () => { vite.kill(); process.exit(); });
}
launch();
process.on('SIGINT', () => { vite.kill(); if (electron) electron.kill(); process.exit(); });
