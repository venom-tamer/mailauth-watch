// End-to-end browser test of the checker page. DNS-over-HTTPS calls are intercepted and
// answered from a fixture zone, so the test is deterministic and needs no network.
// Run: npm run test:e2e   (uses the Playwright + Chromium installed on the machine)
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { extname, join, normalize } from 'node:path';
import { execSync } from 'node:child_process';
import assert from 'node:assert/strict';

const require = createRequire(import.meta.url);
let chromium;
try { ({ chromium } = require('playwright')); } catch { ({ chromium } = require(join(execSync('npm root -g').toString().trim(), 'playwright'))); }

const WEB = new URL('../../web/', import.meta.url).pathname;
const TYPES = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.xml': 'application/xml', '.txt': 'text/plain' };
const server = createServer(async (req, res) => {
  let p = decodeURIComponent(new URL(req.url, 'http://x').pathname);
  if (p.endsWith('/')) p += 'index.html';
  const file = normalize(join(WEB, p));
  if (!file.startsWith(WEB)) { res.writeHead(403).end(); return; }
  try { const body = await readFile(file); res.writeHead(200, { 'content-type': TYPES[extname(file)] || 'application/octet-stream' }).end(body); }
  catch { res.writeHead(404).end('not found'); }
});
await new Promise((r) => server.listen(0, '127.0.0.1', r));
const BASE = `http://127.0.0.1:${server.address().port}`;

const ZONE = {
  'TXT neglected.com': ['v=spf1 include:gone.example ptr +all'],
  'MX neglected.com': ['10 mx.neglected.com'],
  'TXT healthy.com': ['v=spf1 include:_spf.google.com -all'],
  'TXT _spf.google.com': ['v=spf1 ip4:74.125.0.0/16 ~all'],
  'TXT _dmarc.healthy.com': ['v=DMARC1; p=reject; rua=mailto:d@healthy.com'],
  'MX healthy.com': ['1 smtp.google.com.'],
  'TXT google._domainkey.healthy.com': ['v=DKIM1; k=rsa; p=' + 'A'.repeat(392)],
  'TXT _mta-sts.healthy.com': ['v=STSv1; id=1'],
  'TXT _smtp._tls.healthy.com': ['v=TLSRPTv1; rua=mailto:t@healthy.com'],
  'TXT xss.com': ['v=spf1 include:<img src=x onerror=alert(1)>.com ~all'],
};
const CODE = { TXT: 16, MX: 15 };
const quote = (s) => s.match(/.{1,255}/g).map((c) => `"${c.replace(/"/g, '\\"')}"`).join(' ');
let dnsDown = false;
const dohCalls = [];
async function doh(route) {
  const u = new URL(route.request().url());
  const name = u.searchParams.get('name').toLowerCase(); const type = u.searchParams.get('type');
  dohCalls.push(`${type} ${name}`);
  if (dnsDown) return route.abort('failed');
  const recs = ZONE[`${type} ${name}`];
  const body = recs ? { Status: 0, Answer: recs.map((r) => ({ name, type: CODE[type], TTL: 300, data: type === 'TXT' ? quote(r) : r })) } : { Status: 3 };
  await route.fulfill({ status: 200, contentType: 'application/dns-json', headers: { 'access-control-allow-origin': '*' }, body: JSON.stringify(body) });
}

const browser = await chromium.launch({ executablePath: process.env.CHROMIUM_PATH || undefined, args: ['--no-sandbox'] });
const results = [];
async function scenario(name, fn, viewport = { width: 1280, height: 900 }) {
  const ctx = await browser.newContext({ viewport });
  const page = await ctx.newPage();
  const errors = [];
  page.on('pageerror', (e) => errors.push(String(e)));
  page.on('dialog', (d) => { errors.push(`dialog opened: ${d.message()}`); d.dismiss(); });
  await page.route(/cloudflare-dns\.com|dns\.google/, doh);
  try {
    await fn(page);
    assert.deepEqual(errors, [], 'no page errors');
    results.push(['ok', name]);
  } catch (e) {
    results.push(['FAIL', name, e.message.split('\n')[0]]);
    await page.screenshot({ path: `${process.env.SHOT_DIR || '/tmp'}/fail-${name.replace(/\W+/g, '-')}.png`, fullPage: true }).catch(() => {});
  }
  await ctx.close();
}

await scenario('neglected domain gets F with critical fixes and a suggested record', async (page) => {
  await page.goto(BASE + '/');
  await page.fill('#domain', 'https://www.Neglected.com/contact');
  await page.click('#check-btn');
  await page.waitForSelector('.grade');
  assert.equal(await page.textContent('.grade'), 'F');
  assert.equal(await page.inputValue('#domain'), 'neglected.com');
  const issues = await page.$$eval('.issue', (els) => els.map((e) => e.textContent));
  for (const needle of ['+all', 'no DMARC record', 'publishes no SPF record', 'ptr', 'No DKIM key']) assert.ok(issues.some((t) => t.includes(needle)), needle);
  assert.ok(!(await page.textContent('#results')).includes('Suggested record'));
  assert.match(page.url(), /\?d=neglected\.com$/);
  assert.equal(await page.textContent('#cta-watch'), 'Monitoring opens soon');
  await page.screenshot({ path: `${process.env.SHOT_DIR || '/tmp'}/desktop-neglected.png`, fullPage: true });
});

await scenario('healthy domain gets A, shows provider and lookup tree; ?d= runs on load', async (page) => {
  await page.goto(BASE + '/?d=healthy.com');
  await page.waitForSelector('.grade');
  assert.equal(await page.textContent('.grade'), 'A');
  const text = await page.textContent('#results');
  assert.ok(text.includes('Google Workspace'));
  assert.ok(text.includes('SPF lookups: 1 of 10'));
  assert.ok(text.includes('No problems found'));
  assert.ok(text.includes('google._domainkey'));
});

await scenario('invalid input shows an error and makes no DNS calls', async (page) => {
  dohCalls.length = 0;
  await page.goto(BASE + '/');
  await page.fill('#domain', 'not a domain');
  await page.click('#check-btn');
  assert.ok(await page.isVisible('#form-error'));
  assert.equal(dohCalls.length, 0);
});

await scenario('DNS data is rendered as text, never as HTML', async (page) => {
  await page.goto(BASE + '/?d=xss.com');
  await page.waitForSelector('.grade');
  assert.equal(await page.$$eval('#results img', (e) => e.length), 0);
  assert.ok((await page.textContent('#results')).includes('<img src=x onerror=alert(1)>'));
});

await scenario('DNS outage degrades to warnings instead of a broken page', async (page) => {
  dnsDown = true;
  await page.goto(BASE + '/?d=healthy.com');
  await page.waitForSelector('.grade');
  assert.ok((await page.textContent('#results')).includes('Could not look up'));
  dnsDown = false;
});

await scenario('checkout link gets UTM tags when configured', async (page) => {
  await page.route('**/assets/config.js', (r) => r.fulfill({ contentType: 'text/javascript', body: "export default { checkoutUrl: 'https://buy.polar.sh/polar_cl_test', priceLabel: '$5', analytics: {} };" }));
  await page.goto(BASE + '/?d=healthy.com');
  await page.waitForSelector('.upsell .btn[href]');
  const href = await page.getAttribute('.upsell .btn', 'href');
  assert.equal(href, 'https://buy.polar.sh/polar_cl_test?utm_source=mailauth-watch&utm_content=results');
  assert.match(await page.getAttribute('#cta-watch', 'href'), /utm_content=pricing/);
});

await scenario('mobile 360px: no horizontal scroll, form usable', async (page) => {
  await page.goto(BASE + '/?d=neglected.com');
  await page.waitForSelector('.grade');
  const { sw, iw } = await page.evaluate(() => ({ sw: document.documentElement.scrollWidth, iw: window.innerWidth }));
  assert.ok(sw <= iw, `scrollWidth ${sw} > ${iw}`);
  const box = await page.locator('#check-btn').boundingBox();
  assert.ok(box.height >= 40, 'tap target at least 40px tall');
  await page.screenshot({ path: `${process.env.SHOT_DIR || '/tmp'}/mobile-neglected.png`, fullPage: true });
}, { width: 360, height: 780 });

await scenario('privacy and terms pages load', async (page) => {
  for (const p of ['/privacy.html', '/terms.html']) {
    const r = await page.goto(BASE + p);
    assert.equal(r.status(), 200);
  }
});

await browser.close();
server.close();
for (const r of results) console.log(r.join('  '));
const failed = results.filter((r) => r[0] !== 'ok').length;
console.log(`\n${results.length - failed} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);
