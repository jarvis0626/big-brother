const { spawnSync } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');
const root = path.resolve(__dirname, '..');
const cache = path.join(root, '.cache');
const env = { ...process.env, ELECTRON_CACHE: path.join(cache, 'electron'),
  ELECTRON_BUILDER_CACHE: path.join(cache, 'electron-builder'), TEMP: path.join(cache, 'temp'),
  TMP: path.join(cache, 'temp'), CSC_IDENTITY_AUTO_DISCOVERY: 'false' };
fs.mkdirSync(env.TEMP, { recursive: true });
const target = process.argv.includes('--dir') ? ['dir'] : ['nsis', 'portable'];
const r = spawnSync(process.execPath, [path.join(root, 'node_modules', 'electron-builder', 'cli.js'), '--win', ...target, '--x64', '--publish', 'never'], { cwd: root, env, stdio: 'inherit' });
process.exit(r.status ?? 1);
