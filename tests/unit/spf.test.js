import { test } from 'node:test';
import assert from 'node:assert/strict';
import { analyzeSpf, parseSpf, flattenTree } from '../../web/core/spf.js';
import { mockResolver } from './mock-resolver.js';

const codes = (r) => r.issues.map((i) => i.code);

test('parses mechanisms, qualifiers, modifiers and CIDR forms', () => {
  const t = parseSpf('v=spf1 ip4:1.2.3.0/24 a/24 mx:mail.example.com -include:x.com redirect=y.com ~all');
  assert.deepEqual(t.map((x) => [x.kind, x.qualifier, x.name, x.value]), [
    ['mechanism', '+', 'ip4', '1.2.3.0'],
    ['mechanism', '+', 'a', ''],
    ['mechanism', '+', 'mx', 'mail.example.com'],
    ['mechanism', '-', 'include', 'x.com'],
    ['modifier', '', 'redirect', 'y.com'],
    ['mechanism', '~', 'all', ''],
  ]);
});

test('counts nested include lookups across the whole tree', async () => {
  const r = mockResolver({
    'TXT example.com': ['v=spf1 include:a.net include:b.net mx ~all', 'google-site-verification=x'],
    'TXT a.net': ['v=spf1 include:a1.net include:a2.net -all'],
    'TXT a1.net': ['v=spf1 ip4:1.1.1.1 -all'],
    'TXT a2.net': ['v=spf1 ip4:2.2.2.2 -all'],
    'TXT b.net': ['v=spf1 ip4:3.3.3.3 ~all'],
    'MX example.com': ['10 mx.example.com'],
  });
  const res = await analyzeSpf('example.com', r);
  assert.equal(res.lookups, 5); // a.net, a1, a2, b.net, mx
  assert.deepEqual(codes(res), []);
  assert.deepEqual(flattenTree(res.tree).map((n) => [n.domain, n.depth]), [
    ['example.com', 0], ['a.net', 1], ['a1.net', 2], ['a2.net', 2], ['b.net', 1],
  ]);
});

test('flags more than 10 lookups as critical permerror', async () => {
  const zone = { 'TXT example.com': [`v=spf1 ${Array.from({ length: 11 }, (_, i) => `include:s${i}.net`).join(' ')} ~all`] };
  for (let i = 0; i < 11; i++) zone[`TXT s${i}.net`] = ['v=spf1 ip4:1.1.1.1 -all'];
  const res = await analyzeSpf('example.com', mockResolver(zone));
  assert.equal(res.lookups, 11);
  assert.ok(codes(res).includes('spf-too-many-lookups'));
});

test('warns at 9 or 10 lookups', async () => {
  const zone = { 'TXT example.com': [`v=spf1 ${Array.from({ length: 9 }, (_, i) => `include:s${i}.net`).join(' ')} ~all`] };
  for (let i = 0; i < 9; i++) zone[`TXT s${i}.net`] = ['v=spf1 ip4:1.1.1.1 -all'];
  const res = await analyzeSpf('example.com', mockResolver(zone));
  assert.ok(codes(res).includes('spf-near-limit'));
});

test('missing SPF, multiple SPF, +all, ?all, no all, ptr', async () => {
  assert.ok(codes(await analyzeSpf('a.com', mockResolver({ 'TXT a.com': ['hello'] }))).includes('spf-missing'));
  assert.ok(codes(await analyzeSpf('a.com', mockResolver({ 'TXT a.com': ['v=spf1 -all', 'v=spf1 ~all'] }))).includes('spf-multiple'));
  assert.ok(codes(await analyzeSpf('a.com', mockResolver({ 'TXT a.com': ['v=spf1 ip4:1.1.1.1 +all'] }))).includes('spf-plus-all'));
  assert.ok(codes(await analyzeSpf('a.com', mockResolver({ 'TXT a.com': ['v=spf1 ip4:1.1.1.1 ?all'] }))).includes('spf-neutral-all'));
  assert.ok(codes(await analyzeSpf('a.com', mockResolver({ 'TXT a.com': ['v=spf1 ip4:1.1.1.1'] }))).includes('spf-no-all'));
  assert.ok(codes(await analyzeSpf('a.com', mockResolver({ 'TXT a.com': ['v=spf1 ptr ~all'] }))).includes('spf-ptr'));
});

test('include pointing at a domain without SPF is a permerror and counts as void', async () => {
  const res = await analyzeSpf('a.com', mockResolver({ 'TXT a.com': ['v=spf1 include:gone.net ~all'] }));
  assert.ok(codes(res).includes('spf-include-missing'));
  assert.equal(res.voidLookups, 1);
});

test('detects include loops without hanging', async () => {
  const res = await analyzeSpf('a.com', mockResolver({
    'TXT a.com': ['v=spf1 include:b.com ~all'],
    'TXT b.com': ['v=spf1 include:a.com ~all'],
  }));
  assert.ok(codes(res).includes('spf-loop'));
});

test('macros are counted but not followed; redirect followed only without all', async () => {
  const r1 = await analyzeSpf('a.com', mockResolver({ 'TXT a.com': ['v=spf1 exists:%{i}._spf.a.com include:%{d}.x.net -all'] }));
  assert.equal(r1.lookups, 2);
  const r2 = await analyzeSpf('a.com', mockResolver({ 'TXT a.com': ['v=spf1 redirect=b.com'], 'TXT b.com': ['v=spf1 include:c.com -all'], 'TXT c.com': ['v=spf1 -all'] }));
  assert.equal(r2.lookups, 2);
  assert.deepEqual(codes(r2), []);
  const r3 = await analyzeSpf('a.com', mockResolver({ 'TXT a.com': ['v=spf1 -all redirect=b.com'] }));
  assert.equal(r3.lookups, 0);
});

test('DNS errors are reported as warnings, not as a missing record', async () => {
  const res = await analyzeSpf('a.com', mockResolver({}, { errors: ['TXT a.com'] }));
  assert.ok(codes(res).includes('spf-dns-error'));
  assert.ok(!codes(res).includes('spf-missing'));
});

test('unknown terms are syntax errors', async () => {
  const res = await analyzeSpf('a.com', mockResolver({ 'TXT a.com': ['v=spf1 inlcude:x.com ~all'] }));
  assert.ok(codes(res).includes('spf-syntax'));
});
