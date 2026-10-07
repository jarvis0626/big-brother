const test = require('node:test');
const assert = require('node:assert/strict');
const { validateRequest, validateExternal } = require('../desktop/security.cjs');
test('renderer cannot launch arbitrary binaries or invoke service methods', () => {
  for (const method of ['launch','shutdown','export','exec','constructor','__proto__']) assert.throws(() => validateRequest(method, { path: 'cmd.exe' }));
  assert.throws(() => validateRequest('watch', { pid: 12, command: 'malicious' }));
  for (const pid of [0,-1,1.2,'12',NaN,Infinity,2**34]) assert.throws(() => validateRequest('watch',{pid}));
  assert.deepEqual(validateRequest('watch',{pid:12}),{pid:12});
});
test('settings and report references reject malformed or excessive input', () => {
  assert.throws(() => validateRequest('settings',{retention_days:-1}));
  assert.throws(() => validateRequest('settings',{remote_key:'secret'}));
  assert.throws(() => validateRequest('pause',{session_id:'../../secrets',paused:true}));
  assert.throws(() => validateRequest('state',{session_id:'a'.repeat(10000)}));
  assert.deepEqual(validateRequest('replay',{}),{scenario:'investigation'});
});
test('only curated secure documentation can open outside the app', () => {
  for (const url of ['file:///C:/Windows/system32/cmd.exe','javascript:alert(1)','https://example.com','https://attack.mitre.org.evil.test','https://attack.mitre.org:9999','https://user:password@attack.mitre.org','https://github.com/attacker/run']) assert.throws(() => validateExternal(url));
  assert.equal(validateExternal('https://attack.mitre.org/techniques/T1547/'),'https://attack.mitre.org/techniques/T1547/');
});
