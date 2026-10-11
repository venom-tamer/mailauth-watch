// Smoke test of the deployed site with real DNS-over-HTTPS (no fixtures).
// Run: SITE_URL=https://... node tests/e2e/live.mjs
import { createRequire } from 'node:module';
import { join } from 'node:path';
import { execSync } from 'node:child_process';
import assert from 'node:assert/strict';

const require = createRequire(import.meta.url);
let chromium;
try { ({ chromium } = require('playwright')); } catch { ({ chromium } = require(join(execSync('npm root -g').toString().trim(), 'playwright'))); }

const BASE = (process.env.SITE_URL || '').replace(/\/+$/, '');
if (!/^https:\/\//.test(BASE)) { console.error('SITE_URL must be an https URL'); process.exit(1); }

const results = [];
async function check(name, fn) {
  try { await fn(); results.push(['ok', name]); }
  catch (e) { results.push(['FAIL', name, e.message.split('\n')[0]]); }
}

for (const path of ['/', '/privacy.html', '/terms.html', '/sitemap.xml', '/robots.txt', '/assets/config.js', '/providers/']) {
  await check(`GET ${path} is 200`, async () => {
    const r = await fetch(BASE + path);
    assert.equal(r.status, 200, `status ${r.status}`);
  });
}
await check('sitemap lists provider pages', async () => {
  const xml = await (await fetch(BASE + '/sitemap.xml')).text();
  assert.match(xml, /\/providers\//);
});

{
  // Public info: which Polar environment the site's checkout button points at.
  const js = await (await fetch(BASE + '/assets/config.js')).text().catch(() => '');
  const host = (js.match(/https:\/\/([a-z0-9.-]*polar\.sh)\//) || [])[1] || 'none';
  const kind = host === 'none' ? 'not set' : host.includes('sandbox') ? 'SANDBOX (test mode, no real payments)' : 'production';
  if (process.env.GITHUB_ACTIONS) console.log(`::notice title=Checkout link::${host} (${kind})`);
  console.log(`checkout link: ${host} (${kind})`);
}
if (process.env.EXPECT_CHECKOUT === '1') {
  await check('checkout link is configured', async () => {
    const js = await (await fetch(BASE + '/assets/config.js')).text();
    assert.match(js, /["']?checkoutUrl["']?: ["']https:\/\/([a-z0-9-]+\.)*polar\.sh\//);
  });
}

const browser = await chromium.launch({ args: ['--no-sandbox'] });
async function page(name, fn) {
  const ctx = await browser.newContext({ viewport: { width: 1280, height: 900 } });
  const p = await ctx.newPage();
  const errors = [];
  p.on('pageerror', (e) => errors.push(String(e)));
  await check(name, async () => { await fn(p); assert.deepEqual(errors, [], 'no page errors'); });
  await p.screenshot({ path: `${process.env.SHOT_DIR || '/tmp'}/live-${name.replace(/\W+/g, '-')}.png`, fullPage: true }).catch(() => {});
  await ctx.close();
}

for (const d of ['google.com', 'github.com']) {
  await page(`real DNS audit of ${d} renders a grade`, async (p) => {
    await p.goto(`${BASE}/?d=${d}`);
    await p.waitForSelector('.grade', { timeout: 30000 });
    const grade = (await p.textContent('.grade')).trim();
    assert.match(grade, /^[A-F]$/);
    const text = await p.textContent('#results');
    assert.match(text, /SPF/);
    console.log(`  ${d}: grade ${grade}`);
  });
}
await page('manual entry works', async (p) => {
  await p.goto(BASE + '/');
  await p.fill('#domain', 'https://www.Microsoft.com/');
  await p.click('#check-btn');
  await p.waitForSelector('.grade', { timeout: 30000 });
  assert.equal(await p.inputValue('#domain'), 'microsoft.com');
});
await browser.close();

for (const r of results) console.log(r.join('  '));
const failed = results.filter((r) => r[0] !== 'ok').length;
console.log(`${results.length - failed}/${results.length} live checks passed`);
process.exit(failed ? 1 : 0);
