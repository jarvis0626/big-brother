// Lock direct dependency versions to the successfully installed resolution.
const fs = require('node:fs');
const path = require('node:path');
const root = path.resolve(__dirname, '..');
const p = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
const lock = JSON.parse(fs.readFileSync(path.join(root, 'package-lock.json'), 'utf8'));
for (const section of ['dependencies', 'devDependencies']) {
  for (const name of Object.keys(p[section])) {
    p[section][name] = lock.packages['node_modules/' + name].version;
    console.log(name + ' ' + p[section][name]);
  }
}
fs.writeFileSync(path.join(root, 'package.json'), JSON.stringify(p, null, 2) + '\n');
