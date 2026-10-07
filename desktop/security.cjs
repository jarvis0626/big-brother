'use strict';
const EXTERNAL_HOSTS = new Set(['learn.microsoft.com', 'attack.mitre.org', 'csr.lanl.gov']);
const ALLOWED = new Set(['state', 'list_processes', 'watch', 'replay', 'pause', 'stop', 'settings', 'delete_session']);
const SETTINGS = {
  retention_days: [1, 90], max_events: [500, 100000], poll_interval: [0.5, 10],
  max_queue: [128, 16384], max_sessions: [1, 100]
};
function validId(value) { return typeof value === 'string' && /^[a-zA-Z0-9_:.-]{1,160}$/.test(value); }
function validateRequest(method, input = {}) {
  if (!ALLOWED.has(method)) throw new Error('Unsupported action');
  if (!input || typeof input !== 'object' || Array.isArray(input)) throw new Error('Invalid action parameters');
  if (JSON.stringify(input).length > 4096) throw new Error('Action is too large');
  const out = {};
  const acceptId = () => { if (!validId(input.session_id)) throw new Error('Invalid session'); out.session_id = input.session_id; };
  const keys = {
    state: ['session_id'], list_processes: [], watch: ['pid'], replay: ['scenario'],
    pause: ['session_id', 'paused'], stop: ['session_id'], settings: [...Object.keys(SETTINGS), 'close_to_tray', 'llm_provider'], delete_session: ['session_id']
  }[method];
  for (const key of Object.keys(input)) if (!keys.includes(key)) throw new Error('Unexpected action parameter');
  if (['state', 'stop'].includes(method) && input.session_id !== undefined) acceptId();
  if (['pause', 'delete_session'].includes(method)) acceptId();
  if (method === 'pause') { if (typeof input.paused !== 'boolean') throw new Error('Invalid pause state'); out.paused = input.paused; }
  if (method === 'watch') { if (!Number.isSafeInteger(input.pid) || input.pid <= 0 || input.pid > 0xffffffff) throw new Error('Invalid process'); out.pid = input.pid; }
  if (method === 'replay') { if (input.scenario !== undefined && !['ordinary', 'investigation'].includes(input.scenario)) throw new Error('Invalid replay'); out.scenario = input.scenario || 'investigation'; }
  if (method === 'settings') for (const [key, value] of Object.entries(input)) {
    if (key === 'close_to_tray') { if (typeof value !== 'boolean') throw new Error('Invalid close preference'); out[key] = value; continue; }
    if (key === 'llm_provider') { if (value !== 'disabled') throw new Error('External requests require separate opt-in'); out[key] = value; continue; }
    const [min, max] = SETTINGS[key];
    if (typeof value !== 'number' || !Number.isFinite(value) || value < min || value > max || (key !== 'poll_interval' && !Number.isInteger(value))) throw new Error('Invalid setting');
    out[key] = value;
  }
  return out;
}
function validateExternal(input) {
  if (typeof input !== 'string' || input.length > 2048) throw new Error('Invalid documentation link');
  let u; try { u = new URL(input); } catch { throw new Error('Invalid documentation link'); }
  if (u.protocol !== 'https:' || u.username || u.password || u.port) throw new Error('Only secure documentation links are allowed');
  if (!EXTERNAL_HOSTS.has(u.hostname) && !(u.hostname === 'github.com' && u.pathname.startsWith('/FiveDirections/OpTC-data'))) throw new Error('Documentation site is not allowed');
  return u.href;
}
module.exports = { validateRequest, validateExternal, validId };
