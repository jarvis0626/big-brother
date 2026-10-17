'use strict';
// Capture real application views using only its built-in fabricated sample.
const { _electron: electron } = require('playwright');
const { spawnSync } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');
const assert = require('node:assert/strict');
const root = path.resolve(__dirname, '..');
const scratch = path.join(root, '.cache', 'demo-recording-' + Date.now());
const output = path.join(root, 'docs', 'media');
fs.mkdirSync(scratch, { recursive: true });
fs.mkdirSync(output, { recursive: true });
const env = { ...process.env, BB_DATA_DIR: path.join(scratch, 'data'), TEMP: path.join(root, '.cache', 'temp'), TMP: path.join(root, '.cache', 'temp') };
delete env.ELECTRON_RUN_AS_NODE;
delete env.BB_DEV;
const executable = process.env.BB_DEMO_EXE || require('electron');
const args = process.env.BB_DEMO_EXE ? [] : [root];
let app;
const evidence = { fabricated_replay: true, captured_from: 'Actual Big Brother desktop UI', steps: [], renderer_errors: [] };

async function main() {
  app = await electron.launch({ executablePath: executable, args, env, timeout: 60000 });
  const page = await app.firstWindow();
  await page.waitForFunction(() => !!window.bigBrother);
  page.on('pageerror', error => evidence.renderer_errors.push(error.message));
  const scenes = { overview: [], evidence: [] };
  async function frame(group, description, seconds = 2) {
    await page.waitForTimeout(450);
    const filename = path.join(scratch, group + '-' + scenes[group].length + '.png');
    await page.screenshot({ path: filename, fullPage: false });
    scenes[group].push({ filename, seconds });
    evidence.steps.push({ group, description });
    console.log('Captured: ' + description);
  }
  await page.getByRole('button', { name: /Explore a replay/ }).waitFor();
  await frame('overview', 'Start with the home screen');
  await page.getByRole('button', { name: /Explore a replay/ }).click();
  const dialog = page.getByRole('dialog', { name: 'Open a replay' });
  await dialog.getByRole('button', { name: /^Investigation/ }).click();
  await frame('overview', 'Choose the sample investigation');
  await dialog.getByRole('button', { name: 'Open replay', exact: true }).click();
  await dialog.waitFor({ state: 'hidden' });
  await page.locator('.replay-notice').waitFor();
  await page.waitForFunction(() => document.querySelectorAll('.process-node').length === 4);
  const state = await page.evaluate(() => window.bigBrother.invoke('state', {}));
  assert.equal(state.session.mode, 'replay');
  assert(state.events.length >= 13);
  evidence.app_version = await app.evaluate(({ app }) => app.getVersion());
  evidence.model_version = state.model.version;
  await frame('overview', 'Follow the four-process graph and recorded timeline', 3);
  const nav = page.getByRole('navigation', { name: 'Main navigation' });
  await nav.getByRole('button', { name: /^Findings/ }).click();
  await page.locator('.finding-summary').first().waitFor();
  await frame('overview', 'Review the list of findings', 3);
  const finding = state.incidents.find(item => item.score_kind === 'rule_reference');
  assert(finding);
  await page.locator('.finding-summary').filter({ hasText: finding.title }).click();
  await frame('overview', 'Read the observed facts and possible explanations', 3);
  await page.getByRole('button', { name: 'View all evidence', exact: true }).click();
  await page.getByRole('heading', { name: 'Activity overview', exact: true }).waitFor();
  await page.locator('.filter-notice').getByRole('button', { name: /Clear filter/ }).click();
  await page.getByRole('button', { name: /Explore a replay/ }).click();
  const networkDialog = page.getByRole('dialog', { name: 'Open a replay' });
  await networkDialog.getByRole('button', { name: /^Online connections/ }).click();
  await networkDialog.getByRole('button', { name: 'Open replay', exact: true }).click();
  await networkDialog.waitFor({ state: 'hidden' });
  await page.locator('.behavior-choice').waitFor();
  const networkState = await page.evaluate(() => window.bigBrother.invoke('state', {}));
  const note = networkState.behavior_notes.find(item => item.classification === 'reference_note');
  assert(note);
  await page.locator('.behavior-choice').filter({ hasText: note.title }).click();
  await frame('evidence', 'Read a neutral behavior note separately from rule findings', 3);
  const eventId = note.explanation.observed[0].event_ids[0];
  await page.getByTitle('Show event ' + eventId, { exact: true }).first().click();
  await page.getByRole('heading', { name: 'Event details', exact: true }).waitFor();
  assert.equal(await page.locator('.event-selected').getAttribute('data-event-id'), eventId);
  await frame('evidence', 'Click a reference to inspect its exact supporting event', 3);
  await page.getByRole('button', { name: 'Close event details', exact: true }).click();
  const reportPath = path.join(scratch, 'sample-report.json');
  await app.evaluate(({ dialog }, filePath) => {
    dialog.showSaveDialog = async () => ({ canceled: false, filePath });
  }, reportPath);
  await page.locator('.session-controls').getByRole('button', { name: 'Export', exact: true }).click();
  await page.waitForFunction(() => document.querySelector('.toast')?.textContent.includes('Report exported'));
  assert.equal(JSON.parse(fs.readFileSync(reportPath, 'utf8')).session.mode, 'replay');
  await frame('evidence', 'Export a local report; native destination selected by capture harness', 2);
  await nav.getByRole('button', { name: 'Sessions', exact: true }).click();
  await frame('evidence', 'Return to a saved investigation through Sessions', 3);
  assert.deepEqual(evidence.renderer_errors, []);
  await app.close();
  app = null;
  for (const [group, frames] of Object.entries(scenes)) {
    const playlist = frames.map(item => "file '" + item.filename.replaceAll('\\', '/') + "'\nduration " + item.seconds).join('\n')
      + "\nfile '" + frames.at(-1).filename.replaceAll('\\', '/') + "'\n";
    const input = path.join(scratch, group + '.txt');
    fs.writeFileSync(input, playlist);
    const result = spawnSync('ffmpeg', ['-hide_banner', '-loglevel', 'error', '-y', '-f', 'concat', '-safe', '0', '-i', input,
      '-filter_complex', 'fps=3,scale=1000:-1:flags=lanczos,split[a][b];[a]palettegen=max_colors=128[p];[b][p]paletteuse=dither=bayer:bayer_scale=4',
      '-loop', '0', path.join(output, group + '.gif')], { cwd: root, encoding: 'utf8', timeout: 120000, windowsHide: true });
    if (result.status !== 0) throw new Error('GIF encoding failed: ' + result.stderr);
    console.log(group + '.gif: ' + fs.statSync(path.join(output, group + '.gif')).size + ' bytes');
  }
  evidence.recorded_at_utc = new Date().toISOString();
  evidence.native_save_dialog_automated = true;
  fs.writeFileSync(path.join(output, 'capture.json'), JSON.stringify(evidence, null, 2) + '\n');
}
main().catch(async error => {
  if (app) await app.close().catch(() => {});
  console.error(error.message);
  process.exitCode = 1;
});
