import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, readdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { pathToFileURL } from 'node:url';
import { runMonitor } from '../../src/node/monitor.js';
import { listActiveSubscribers, listOrders } from '../../src/node/polar.js';
import { createMailer } from '../../src/node/mailer.js';
import { buildReport } from '../../src/node/report.js';
import { measureProviders, mergeHistory, writeSite } from '../../scripts/build-provider-pages.mjs';
import { mockResolver } from './mock-resolver.js';

const CANARY = { 'TXT spf.protection.outlook.com': ['v=spf1 ip4:40.92.0.0/15 -all'] };
const zoneGood = {
  'TXT spf.protection.outlook.com': ['v=spf1 ip4:40.92.0.0/15 -all'],
  'TXT shop.com': ['v=spf1 include:_spf.google.com ~all'],
  'TXT _spf.google.com': ['v=spf1 ip4:74.125.0.0/16 ~all'],
  'TXT _dmarc.shop.com': ['v=DMARC1; p=quarantine; rua=mailto:d@shop.com'],
  'MX shop.com': ['1 smtp.google.com'],
  'TXT google._domainkey.shop.com': ['v=DKIM1; p=' + 'A'.repeat(392)],
};
const ctx = { siteUrl: 'https://site.test', portalUrl: 'https://polar.test/portal' };
function fakeMailer({ fail = false } = {}) {
  const sent = [];
  return { sent, mode: 'test', async send(m) { if (fail) return { ok: false, error: 'boom' }; sent.push(m); return { ok: true }; } };
}
const clock = (iso) => () => new Date(iso);
const subs = [{ subscriptionId: 'sub_1', email: 'owner@shop.com', domain: 'https://www.Shop.com/' }];

test('welcome, then silence, then alert on change, then weekly digest', async () => {
  const m = fakeMailer();
  let r = await runMonitor({ subscribers: subs, state: {}, resolver: mockResolver(zoneGood), mailer: m, ctx, now: clock('2026-10-01T06:00:00Z') });
  assert.equal(m.sent.length, 1);
  assert.match(m.sent[0].subject, /Now watching shop\.com \(grade A\)/);
  assert.match(m.sent[0].text, /https:\/\/site\.test\/\?d=shop\.com/);

  r = await runMonitor({ subscribers: subs, state: r.state, resolver: mockResolver(zoneGood), mailer: m, ctx, now: clock('2026-10-02T06:00:00Z') });
  assert.equal(m.sent.length, 1, 'no email when nothing changed');

  const broken = { ...zoneGood, 'TXT _dmarc.shop.com': [] };
  r = await runMonitor({ subscribers: subs, state: r.state, resolver: mockResolver(broken), mailer: m, ctx, now: clock('2026-10-03T06:00:00Z') });
  assert.equal(m.sent.length, 2);
  assert.match(m.sent[1].subject, /^Action needed/);
  assert.match(m.sent[1].text, /DMARC record changed/);
  assert.match(m.sent[1].text, /\[CRITICAL\] DMARC/);

  r = await runMonitor({ subscribers: subs, state: r.state, resolver: mockResolver(broken), mailer: m, ctx, now: clock('2026-10-07T06:00:00Z') });
  assert.equal(m.sent.length, 2, 'digest not due 6 days after welcome');
  r = await runMonitor({ subscribers: subs, state: r.state, resolver: mockResolver(broken), mailer: m, ctx, now: clock('2026-10-08T06:00:00Z') });
  assert.equal(m.sent.length, 3);
  assert.match(m.sent[2].subject, /^Weekly: shop\.com/);
});

test('DNS errors never trigger customer alerts and escalate after 3 runs', async () => {
  const m = fakeMailer();
  let r = await runMonitor({ subscribers: subs, state: {}, resolver: mockResolver(zoneGood), mailer: m, ctx, now: clock('2026-10-01T06:00:00Z') });
  for (let i = 0; i < 3; i++) r = await runMonitor({ subscribers: subs, state: r.state, resolver: mockResolver(CANARY, { errors: ['TXT shop.com', 'TXT _dmarc.shop.com', 'MX shop.com'] }), mailer: m, ctx, now: clock(`2026-10-0${2 + i}T06:00:00Z`) });
  assert.equal(m.sent.length, 1);
  assert.equal(r.summary.errors, 1);
  assert.equal(r.state.domains['shop.com'].consecutiveErrors, 3);
});

test('failed sends do not advance state, so the email retries next run', async () => {
  const bad = fakeMailer({ fail: true });
  let r = await runMonitor({ subscribers: subs, state: {}, resolver: mockResolver(zoneGood), mailer: bad, ctx, now: clock('2026-10-01T06:00:00Z') });
  assert.equal(r.summary.emails.failed, 1);
  assert.ok(!r.state.subs.sub_1.welcomedAt);
  const good = fakeMailer();
  r = await runMonitor({ subscribers: subs, state: r.state, resolver: mockResolver(zoneGood), mailer: good, ctx, now: clock('2026-10-01T07:00:00Z') });
  assert.equal(good.sent.length, 1);
});

test('email cap defers extra mail; domain cap and invalid input are reported; cancelled subs are forgotten', async () => {
  const many = Array.from({ length: 5 }, (_, i) => ({ subscriptionId: `s${i}`, email: `u${i}@shop.com`, domain: 'shop.com' }));
  const m = fakeMailer();
  let r = await runMonitor({ subscribers: many, state: {}, resolver: mockResolver(zoneGood), mailer: m, ctx, limits: { maxEmailsPerRun: 2 }, now: clock('2026-10-01T06:00:00Z') });
  assert.equal(m.sent.length, 2);
  assert.equal(r.summary.deferred, 3);
  r = await runMonitor({ subscribers: many, state: r.state, resolver: mockResolver(zoneGood), mailer: m, ctx, limits: { maxEmailsPerRun: 10 }, now: clock('2026-10-01T07:00:00Z') });
  assert.equal(m.sent.length, 5, 'deferred welcomes go out next run, nobody gets two');

  const r2 = await runMonitor({ subscribers: [{ subscriptionId: 'x', email: 'a@b.com', domain: 'not a domain' }, { subscriptionId: 'y', email: null, domain: 'shop.com' }], state: r.state, resolver: mockResolver(zoneGood), mailer: m, ctx });
  assert.equal(r2.summary.needsHuman, 2);
  assert.deepEqual(Object.keys(r2.state.subs), [], 'ended subscriptions removed');

  const capped = await runMonitor({ subscribers: [{ subscriptionId: 'a', email: 'a@a.com', domain: 'a.com' }, { subscriptionId: 'b', email: 'b@b.com', domain: 'b.com' }], state: {}, resolver: mockResolver(CANARY), mailer: fakeMailer(), ctx, limits: { maxDomains: 1 } });
  assert.equal(capped.summary.domainsChecked, 1);
  assert.ok(capped.events.some((e) => e.msg.includes('domain cap')));
});

test('state never stores subscriber emails', async () => {
  const r = await runMonitor({ subscribers: subs, state: {}, resolver: mockResolver(zoneGood), mailer: fakeMailer(), ctx });
  assert.ok(!JSON.stringify(r.state).includes('owner@shop.com'));
});

function fakeFetch(pages) {
  const calls = [];
  return { calls, fetchImpl: async (url, init) => {
    calls.push({ url, auth: init.headers.authorization });
    const page = Number(new URL(url).searchParams.get('page'));
    return { ok: true, json: async () => ({ items: pages[page - 1], pagination: { max_page: pages.length, total_count: 0 } }) };
  } };
}

test('Polar client paginates, filters active subscriptions and reads the domain field', async () => {
  const f = fakeFetch([
    [{ id: 's1', status: 'active', customer: { email: 'a@x.com' }, custom_field_data: { domain: 'x.com' } }, { id: 's2', status: 'canceled', customer: { email: 'b@y.com' }, custom_field_data: { domain: 'y.com' } }],
    [{ id: 's3', status: 'trialing', customer: { email: 'c@z.com' }, custom_field_data: {} }],
  ]);
  const out = await listActiveSubscribers({ token: 'tok', baseUrl: 'https://sandbox-api.polar.sh', fetchImpl: f.fetchImpl });
  assert.deepEqual(out.map((s) => [s.subscriptionId, s.email, s.domain]), [['s1', 'a@x.com', 'x.com'], ['s3', 'c@z.com', null]]);
  assert.equal(f.calls.length, 2);
  assert.equal(f.calls[0].auth, 'Bearer tok');
  assert.match(f.calls[0].url, /^https:\/\/sandbox-api\.polar\.sh\/v1\/subscriptions\/\?/);
  const o = fakeFetch([[{ id: 'o1', status: 'paid', currency: 'usd', net_amount: 500, total_amount: 500, tax_amount: 0, billing_reason: 'subscription_create', created_at: '2026-10-01' }]]);
  const orders = await listOrders({ token: 't', baseUrl: 'https://api.polar.sh', fetchImpl: o.fetchImpl }, '2026-09-01');
  assert.equal(orders[0].netAmount, 500);
  assert.match(o.calls[0].url, /created_after=2026-09-01/);
});

test('mailer writes to the outbox without an API key and calls Resend with one', async () => {
  const dir = mkdtempSync(`${tmpdir()}/outbox-`);
  const m = createMailer({ outboxDir: dir, from: 'x@y.z' });
  assert.equal(m.mode, 'outbox');
  await m.send({ to: 'a@b.c', subject: 's', text: 't' });
  assert.equal(readdirSync(dir).length, 1);
  let req;
  const live = createMailer({ apiKey: 're_test', from: 'x@y.z', fetchImpl: async (url, init) => { req = { url, init }; return { ok: true, json: async () => ({ id: 'e1' }) }; } });
  assert.deepEqual(await live.send({ to: 'a@b.c', subject: 's', text: 't', idempotencyKey: 'k' }), { ok: true, id: 'e1' });
  assert.equal(req.url, 'https://api.resend.com/emails');
  assert.equal(req.init.headers['idempotency-key'], 'k');
  assert.deepEqual(JSON.parse(req.init.body).to, ['a@b.c']);
});

test('report never invents revenue and separates sandbox money', () => {
  const base = { today: '2026-10-11', periodDays: 7, orders: [], subscribers: [], costs: [], monitor: null, providers: null };
  const off = buildReport({ ...base, polarConnected: false });
  assert.match(off, /not measurable; none recorded/);
  const sandbox = buildReport({ ...base, polarConnected: true, polarMode: 'sandbox', orders: [{ status: 'paid', currency: 'usd', netAmount: 500, billingReason: 'subscription_create' }], subscribers: [{}] });
  assert.match(sandbox, /SANDBOX \(test money, not revenue\)/);
  assert.match(sandbox, /5\.00 USD/);
  const live = buildReport({ ...base, polarConnected: true, polarMode: 'production', costs: [{ date: '2026-10-10', item: 'domain', amountUsd: 10.5 }] });
  assert.match(live, /Polar LIVE/);
  assert.match(live, /\$10\.50/);
});

test('provider pages: measured cost, history only grows on change, failed checks keep last good data', async () => {
  const zone = {
    'TXT sendgrid.net': ['v=spf1 ip4:1.1.1.1 include:ab.sendgrid.net ~all'],
    'TXT ab.sendgrid.net': ['v=spf1 ip4:2.2.2.2 ~all'],
    'TXT _spf.google.com': ['v=spf1 ip4:74.125.0.0/16 ~all'],
  };
  const providers = [
    { id: 'sendgrid', name: 'SendGrid', kind: 'sender', spf: 'sendgrid.net' },
    { id: 'google-workspace', name: 'Google Workspace', kind: 'mailbox', spf: '_spf.google.com' },
    { id: 'hubspot', name: 'HubSpot', kind: 'sender', spf: null },
  ];
  const m1 = await measureProviders(mockResolver(zone), providers);
  assert.deepEqual(m1.map((p) => [p.id, p.cost]), [['sendgrid', 2], ['google-workspace', 1]]);
  let d = mergeHistory(null, m1, '2026-10-10');
  d = mergeHistory(d, await measureProviders(mockResolver(zone), providers), '2026-10-11');
  assert.equal(d.providers[0].history.length, 1);
  const changed = { ...zone, 'TXT _spf.google.com': ['v=spf1 include:_netblocks.google.com ~all'], 'TXT _netblocks.google.com': ['v=spf1 ip4:1.2.3.4 ~all'] };
  d = mergeHistory(d, await measureProviders(mockResolver(changed), providers), '2026-10-12');
  const g = d.providers.find((p) => p.id === 'google-workspace');
  assert.equal(g.history.length, 2);
  assert.equal(g.cost, 2);
  d = mergeHistory(d, await measureProviders(mockResolver({}), providers), '2026-10-13');
  assert.ok(d.providers.every((p) => p.stale));
  assert.equal(d.providers.find((p) => p.id === 'google-workspace').cost, 2);

  const site = mkdtempSync(`${tmpdir()}/site-`) + '/';
  writeSite(d, pathToFileURL(site));
  const page = readFileSync(`${site}providers/sendgrid.html`, 'utf8');
  assert.match(page, /costs <strong>2 of your 10<\/strong>/);
  assert.match(page, /SendGrid \+ Google Workspace<\/td><td class="num">4/);
  assert.match(readFileSync(`${site}sitemap.xml`, 'utf8'), /providers\/sendgrid\.html/);
  assert.ok(!page.includes('<script'), 'provider pages ship no scripts');
});

test('a resolver that answers NXDOMAIN for everything aborts the run instead of alarming customers', async () => {
  const m = fakeMailer();
  const r = await runMonitor({ subscribers: subs, state: { subs: { keep: { domain: 'x.com' } } }, resolver: mockResolver({}), mailer: m, ctx });
  assert.equal(m.sent.length, 0);
  assert.equal(r.summary.aborted, 'dns-canary');
  assert.equal(r.summary.errors, 1);
  assert.ok(r.state.subs.keep, 'state untouched');
});

test('SMTP client speaks AUTH PLAIN over the socket, dot-stuffs, and never leaks the password on failure', async () => {
  const { PassThrough } = await import('node:stream');
  const { sendSmtp, buildMessage } = await import('../../src/node/smtp.js');
  function fakeServer(script) {
    const toClient = new PassThrough(); const fromClient = new PassThrough();
    const sock = { written: [], on: (ev, fn) => toClient.on(ev, fn), setEncoding: (e) => toClient.setEncoding(e), write: (d) => { sock.written.push(d); fromClient.write(d); }, end() {}, destroy(e) { toClient.emit('error', e); } };
    let step = 0;
    setImmediate(() => toClient.write(script[step++]));
    fromClient.on('data', () => { if (step < script.length) setImmediate(() => toClient.write(script[step++])); });
    return sock;
  }
  let sock;
  const ok = await sendSmtp({ user: 'brand@gmail.com', pass: 'app-pass', from: 'Brand <brand@gmail.com>', to: 'c@x.com', subject: 'Hi', text: 'line1\n.dot', connect: () => (sock = fakeServer(['220 hi\r\n', '250-smtp\r\n250 AUTH PLAIN\r\n', '235 ok\r\n', '250 ok\r\n', '250 ok\r\n', '354 go\r\n', '250 queued\r\n', '221 bye\r\n'])) });
  assert.deepEqual(ok, { ok: true });
  assert.equal(sock.written[1], `AUTH PLAIN ${Buffer.from('\0brand@gmail.com\0app-pass').toString('base64')}\r\n`);
  assert.equal(sock.written[2], 'MAIL FROM:<brand@gmail.com>\r\n');
  assert.ok(sock.written[5].endsWith('\r\n.\r\n'));
  const bad = await sendSmtp({ user: 'u', pass: 'secret', from: 'a@b.c', to: 'c@d.e', subject: 's', text: 't', connect: () => fakeServer(['220 hi\r\n', '250 ok\r\n', '535 5.7.8 bad credentials\r\n']) });
  assert.equal(bad.ok, false);
  assert.match(bad.error, /AUTH failed: 535/);
  assert.ok(!bad.error.includes(Buffer.from('\0u\0secret').toString('base64')));
  await assert.rejects(() => sendSmtp({ user: 'u', pass: 'p', from: 'a@b.c', to: 'x@y.z\r\nBcc: v@w.x', subject: 's', text: 't', connect: () => fakeServer([]) }), /header injection/);
  const msg = buildMessage({ from: 'a@b.c', to: 'c@d.e', subject: 'Grade A → B', text: 'x' });
  assert.match(msg, /Subject: =\?UTF-8\?B\?/);
  const { createMailer } = await import('../../src/node/mailer.js');
  let got;
  const m = createMailer({ smtp: { user: 'u@gmail.com', pass: 'p' }, from: 'u@gmail.com', smtpSend: async (o) => { got = o; return { ok: true }; } });
  assert.equal(m.mode, 'smtp');
  await m.send({ to: 'c@d.e', subject: 's', text: 't' });
  assert.equal(got.to, 'c@d.e');
});
