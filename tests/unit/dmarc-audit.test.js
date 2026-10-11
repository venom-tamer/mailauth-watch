import { test } from 'node:test';
import assert from 'node:assert/strict';
import { analyzeDmarc, organizationalDomain, parseDmarc } from '../../web/core/dmarc.js';
import { auditDomain, suggestSpf, fingerprint, gradeFor } from '../../web/core/audit.js';
import { joinTxtData, normalizeDomain, isValidDomain, createDohResolver } from '../../web/core/dns.js';
import { mockResolver } from './mock-resolver.js';

const codes = (r) => r.issues.map((i) => i.code);

test('organizational domain handles common multi-label suffixes', () => {
  assert.equal(organizationalDomain('mail.example.com'), 'example.com');
  assert.equal(organizationalDomain('shop.example.co.uk'), 'example.co.uk');
  assert.equal(organizationalDomain('a.b.example.com.eg'), 'example.com.eg');
  assert.equal(organizationalDomain('example.com'), 'example.com');
});

test('DMARC parsing and policy findings', async () => {
  assert.deepEqual(parseDmarc('v=DMARC1; p=reject; rua=mailto:a@b.com'), { v: 'DMARC1', p: 'reject', rua: 'mailto:a@b.com' });
  assert.ok(codes(await analyzeDmarc('a.com', mockResolver({}))).includes('dmarc-missing'));
  assert.ok(codes(await analyzeDmarc('a.com', mockResolver({ 'TXT _dmarc.a.com': ['v=DMARC1; p=none; rua=mailto:x@a.com'] }))).includes('dmarc-p-none'));
  assert.ok(codes(await analyzeDmarc('a.com', mockResolver({ 'TXT _dmarc.a.com': ['v=DMARC1; p=reject'] }))).includes('dmarc-no-rua'));
  assert.ok(codes(await analyzeDmarc('a.com', mockResolver({ 'TXT _dmarc.a.com': ['v=DMARC1; p=reject; rua=x@a.com'] }))).includes('dmarc-bad-rua'));
  assert.ok(codes(await analyzeDmarc('a.com', mockResolver({ 'TXT _dmarc.a.com': ['v=DMARC1; p=reject', 'v=DMARC1; p=none'] }))).includes('dmarc-multiple'));
  const good = await analyzeDmarc('a.com', mockResolver({ 'TXT _dmarc.a.com': ['v=DMARC1; p=reject; rua=mailto:d@a.com!10m'] }));
  assert.deepEqual(codes(good), []);
});

test('DMARC falls back to the organizational domain and uses sp=', async () => {
  const r = await analyzeDmarc('mail.a.com', mockResolver({ 'TXT _dmarc.a.com': ['v=DMARC1; p=reject; sp=none; rua=mailto:d@a.com'] }));
  assert.equal(r.source, '_dmarc.a.com');
  assert.ok(codes(r).includes('dmarc-p-none'));
});

const healthy = {
  'TXT example.com': ['v=spf1 include:_spf.google.com -all'],
  'TXT _spf.google.com': ['v=spf1 ip4:74.125.0.0/16 ~all'],
  'TXT _dmarc.example.com': ['v=DMARC1; p=reject; rua=mailto:dmarc@example.com'],
  'MX example.com': ['1 smtp.google.com'],
  'TXT google._domainkey.example.com': ['v=DKIM1; k=rsa; p=' + 'A'.repeat(392)],
  'TXT _mta-sts.example.com': ['v=STSv1; id=1'],
  'TXT _smtp._tls.example.com': ['v=TLSRPTv1; rua=mailto:tls@example.com'],
};

test('a healthy Google Workspace domain scores A with provider detected', async () => {
  const rep = await auditDomain('example.com', mockResolver(healthy));
  assert.equal(rep.grade, 'A');
  assert.equal(rep.score, 100);
  assert.deepEqual(rep.providers.map((p) => p.id), ['google-workspace']);
  assert.equal(rep.dkim.found[0].selector, 'google');
  assert.equal(rep.dkim.found[0].bits, 2048);
  assert.equal(rep.spf.lookups, 1);
});

test('a neglected domain scores F with prioritised, fixable findings', async () => {
  const rep = await auditDomain('neglected.com', mockResolver({
    'TXT neglected.com': ['v=spf1 include:gone.example ptr +all'],
    'MX neglected.com': ['10 mx.neglected.com'],
  }));
  assert.equal(rep.grade, 'F');
  assert.equal(rep.issues[0].severity, 'critical');
  for (const c of ['spf-plus-all', 'spf-include-missing', 'spf-ptr', 'dmarc-missing', 'dkim-not-found']) assert.ok(codes(rep).includes(c), c);
  assert.equal(suggestSpf(rep), null, 'never suggest a record that authorises no senders');
});

test('suggestSpf keeps senders, keeps -all, builds a record from MX when none exists', async () => {
  const rep = await auditDomain('example.com', mockResolver(healthy));
  assert.equal(suggestSpf(rep), 'v=spf1 include:_spf.google.com -all');
  const none = await auditDomain('n.com', mockResolver({ 'MX n.com': ['0 n-com.mail.protection.outlook.com'] }));
  assert.equal(suggestSpf(none), 'v=spf1 include:spf.protection.outlook.com ~all');
});

test('fingerprint ignores timestamps but changes when records change', async () => {
  const a = await auditDomain('example.com', mockResolver(healthy), { now: () => new Date(0) });
  const b = await auditDomain('example.com', mockResolver(healthy), { now: () => new Date(1e12) });
  assert.equal(fingerprint(a), fingerprint(b));
  const c = await auditDomain('example.com', mockResolver({ ...healthy, 'TXT _dmarc.example.com': ['v=DMARC1; p=none; rua=mailto:d@example.com'] }));
  assert.notEqual(fingerprint(a), fingerprint(c));
});

test('grades', () => {
  assert.deepEqual([100, 90, 89, 75, 60, 40, 39, 0].map(gradeFor), ['A', 'A', 'B', 'B', 'C', 'D', 'F', 'F']);
});

test('TXT joining, domain normalisation and validation', () => {
  assert.equal(joinTxtData('"v=spf1 include:a.com " "~all"'), 'v=spf1 include:a.com ~all');
  assert.equal(joinTxtData('"a\\"b\\059c"'), 'a"b;c');
  assert.equal(normalizeDomain(' https://www.Example.com/path?q=1 '), 'example.com');
  assert.equal(normalizeDomain('someone@example.org'), 'example.org');
  assert.ok(isValidDomain('example.co.uk'));
  for (const bad of ['', 'localhost', 'exa mple.com', '-a.com', 'a..com', '1.2.3.4', 'x'.repeat(64) + '.com']) assert.ok(!isValidDomain(bad), bad);
});

test('DoH resolver parses answers, maps NXDOMAIN, falls back on failure and caches', async () => {
  let calls = 0;
  const fetchImpl = async (url) => {
    calls++;
    if (url.startsWith('https://bad')) throw new Error('blocked');
    if (url.includes('name=missing.com')) return { ok: true, json: async () => ({ Status: 3 }) };
    return { ok: true, json: async () => ({ Status: 0, Answer: [
      { type: 5, data: 'alias.example.com.' },
      { type: 16, data: '"v=spf1 " "-all"' },
    ] }) };
  };
  const r = createDohResolver({ endpoints: ['https://bad/dns', 'https://good/dns'], fetchImpl });
  assert.deepEqual(await r.resolve('example.com', 'TXT'), { status: 'ok', records: ['v=spf1 -all'] });
  assert.equal((await r.resolve('missing.com', 'TXT')).status, 'nxdomain');
  const before = calls;
  await r.resolve('example.com', 'TXT');
  assert.equal(calls, before);
  const failing = createDohResolver({ endpoints: ['https://bad/x'], fetchImpl });
  assert.equal((await failing.resolve('a.com', 'TXT')).status, 'error');
});
