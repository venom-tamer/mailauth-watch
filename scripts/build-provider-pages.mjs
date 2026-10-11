#!/usr/bin/env node
// Measures every known provider's SPF include live from DNS, records changes over time,
// and generates one static page per provider plus an index and sitemap.
//
// Each page carries data measured on the day it was built (lookup cost, the resolved
// include chain, combined costs with common mailbox providers, change history), so the
// pages hold information that static blog posts don't and go stale without.
//
// Env: SITE_URL (for canonical links and sitemap), DATA_FILE (default data/providers.json)
import { readFileSync, writeFileSync, mkdirSync, existsSync } from 'node:fs';
import { analyzeSpf, flattenTree, subtreeLookups } from '../web/core/spf.js';
import { PROVIDERS } from '../web/core/providers.js';
import { createNodeResolver } from '../src/node/resolver.js';
import { log } from '../src/node/log.js';

const root = new URL('../', import.meta.url);
const SITE = (process.env.SITE_URL || 'https://example.invalid').replace(/\/$/, '');
const DATA_FILE = new URL(process.env.DATA_FILE || 'data/providers.json', root);

export async function measureProviders(resolver, providers = PROVIDERS) {
  const results = [];
  for (const p of providers.filter((x) => x.spf)) {
    const a = await analyzeSpf(p.spf, resolver);
    if (!a.record) {
      results.push({ id: p.id, ok: false, reason: a.tree.status });
      continue;
    }
    results.push({
      id: p.id, ok: true, name: p.name, kind: p.kind, include: p.spf,
      cost: 1 + subtreeLookups(a.tree), // the include itself plus everything it pulls in
      record: a.record,
      chain: flattenTree(a.tree).map((n) => ({ domain: n.domain, depth: n.depth, status: n.status, record: n.record })),
    });
  }
  return results;
}

export function mergeHistory(previous, measured, today) {
  const prev = new Map((previous?.providers || []).map((p) => [p.id, p]));
  const providers = [];
  for (const m of measured) {
    const old = prev.get(m.id);
    if (!m.ok) {
      if (old) providers.push({ ...old, stale: true, staleReason: m.reason });
      continue;
    }
    const history = [...(old?.history || [])];
    const last = history[history.length - 1];
    const sig = JSON.stringify(m.chain.map((c) => c.record));
    if (!last || last.sig !== sig || last.cost !== m.cost) history.push({ date: today, cost: m.cost, sig, record: m.record });
    providers.push({ ...m, checkedAt: today, firstSeen: old?.firstSeen || today, history: history.slice(-50), stale: false });
  }
  return { generatedAt: today, providers };
}

const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);

function layout({ title, description, path, body }) {
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>${esc(title)}</title><meta name="description" content="${esc(description)}">
<link rel="canonical" href="${SITE}${path}"><link rel="stylesheet" href="/assets/styles.css">
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%3E%3Crect width='32' height='32' rx='7' fill='%232456d6'/%3E%3Cpath d='M7 11l9 7 9-7v11H7z' fill='white'/%3E%3C/svg%3E">
</head><body>
<header class="top"><div class="wrap row"><a class="brand" href="/"><span class="logo" aria-hidden="true"></span>MailAuth Watch</a>
<nav aria-label="Main"><a href="/providers/">Provider SPF costs</a><a href="/#pricing">Monitoring</a></nav></div></header>
<main id="main" class="wrap" style="padding-top:24px">${body}</main>
<footer class="wrap foot"><p><a href="/">Free SPF/DKIM/DMARC checker</a> · <a href="/privacy.html">Privacy</a> · <a href="/terms.html">Terms</a></p></footer>
</body></html>
`;
}

function providerPage(p, all) {
  const mailboxes = all.filter((x) => x.kind === 'mailbox' && x.id !== p.id);
  const combos = mailboxes.map((m) => `<tr><td>${esc(p.name)} + ${esc(m.name)}</td><td class="num">${p.cost + m.cost}</td><td>${p.cost + m.cost > 10 ? 'Over the limit' : `${10 - p.cost - m.cost} left`}</td></tr>`).join('');
  const chain = p.chain.map((c) => `<li><span style="padding-left:${c.depth * 16}px">${c.depth ? '└ ' : ''}${esc(c.domain)}</span><span class="cost">${c.status === 'ok' ? '' : esc(c.status)}</span></li>`).join('');
  const records = p.chain.filter((c) => c.record).map((c) => `<p class="fine">${esc(c.domain)}</p><div class="record">${esc(c.record)}</div>`).join('');
  const history = [...p.history].reverse().map((h) => `<tr><td>${esc(h.date)}</td><td class="num">${h.cost}</td><td><code>${esc(h.record)}</code></td></tr>`).join('');
  const body = `
<h1>${esc(p.name)} SPF: how many DNS lookups does it cost?</h1>
<div class="card"><p style="font-size:20px;margin:0"><code>include:${esc(p.include)}</code> costs <strong>${p.cost} of your 10</strong> SPF DNS lookups.</p>
<p class="fine">Measured from live DNS on ${esc(p.checkedAt)}. ${p.stale ? 'The latest check failed; showing the last good measurement.' : 'Re-measured automatically every day.'}</p></div>
<h2>Add ${esc(p.name)} to your SPF record</h2>
<p>Add this term before the <code>~all</code> or <code>-all</code> at the end of your existing SPF record. Don't publish a second SPF record: a domain may have only one.</p>
<div class="record">include:${esc(p.include)}</div>
<h2>What the include resolves to</h2>
<ul class="tree">${chain}</ul>
${records}
<h2>Combined with a mailbox provider</h2>
<div class="table-scroll"><table class="data"><thead><tr><th>Combination</th><th>Lookups</th><th>Budget</th></tr></thead><tbody>${combos}</tbody></table></div>
<p class="fine">Your own record's other terms (a, mx, other includes) add to these totals. <a href="/">Check your whole domain</a> for the exact number.</p>
<h2>Change history</h2>
<div class="table-scroll"><table class="data"><thead><tr><th>Date</th><th>Lookups</th><th>Record</th></tr></thead><tbody>${history}</tbody></table></div>
<div class="upsell"><h3>Providers change these records</h3><p>When an include grows, your SPF can pass the 10-lookup limit without you changing anything. MailAuth Watch re-checks your domain daily and emails you when that happens.</p><a class="btn" href="/#pricing">See monitoring</a></div>`;
  return layout({
    title: `${p.name} SPF include: ${p.cost} DNS lookup${p.cost > 1 ? 's' : ''} (measured ${p.checkedAt})`,
    description: `include:${p.include} uses ${p.cost} of SPF's 10 DNS lookups, measured live on ${p.checkedAt}. See its full include chain, combined totals with Google Workspace and Microsoft 365, and change history.`,
    path: `/providers/${p.id}.html`, body,
  });
}

function indexPage(all) {
  const rows = [...all].sort((a, b) => a.cost - b.cost || a.name.localeCompare(b.name))
    .map((p) => `<tr><td><a href="/providers/${p.id}.html">${esc(p.name)}</a></td><td><code>include:${esc(p.include)}</code></td><td class="num">${p.cost}</td><td>${esc(p.checkedAt)}</td></tr>`).join('');
  const body = `<h1>SPF lookup cost of every major email provider</h1>
<p>SPF allows 10 DNS lookups. This table shows how many each provider's include uses today, measured from live DNS every day, not copied from documentation.</p>
<div class="table-scroll"><table class="data"><thead><tr><th>Provider</th><th>Include</th><th>Lookups</th><th>Measured</th></tr></thead><tbody>${rows}</tbody></table></div>
<p class="fine">HubSpot is not listed because it gives each customer a domain-specific include. <a href="/">Check your domain</a> to measure yours.</p>`;
  return layout({ title: 'SPF DNS lookup cost by email provider (measured daily)', description: 'How many of SPF\'s 10 DNS lookups Google Workspace, Microsoft 365, SendGrid, Mailchimp, Salesforce and others use, measured live every day.', path: '/providers/', body });
}

export function writeSite(data, siteDir = new URL('web/', root)) {
  const OUT_DIR = new URL('providers/', siteDir);
  mkdirSync(OUT_DIR, { recursive: true });
  const live = data.providers;
  for (const p of live) writeFileSync(new URL(`${p.id}.html`, OUT_DIR), providerPage(p, live));
  writeFileSync(new URL('index.html', OUT_DIR), indexPage(live));
  const urls = ['/', '/providers/', ...live.map((p) => `/providers/${p.id}.html`), '/privacy.html', '/terms.html'];
  writeFileSync(new URL('sitemap.xml', siteDir), `<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n${urls.map((u) => `  <url><loc>${SITE}${u}</loc><lastmod>${data.generatedAt}</lastmod></url>`).join('\n')}\n</urlset>\n`);
  writeFileSync(new URL('robots.txt', siteDir), `User-agent: *\nAllow: /\nSitemap: ${SITE}/sitemap.xml\n`);
}

async function main() {
  const today = new Date().toISOString().slice(0, 10);
  const previous = existsSync(DATA_FILE) ? JSON.parse(readFileSync(DATA_FILE, 'utf8')) : null;
  const measured = await measureProviders(createNodeResolver());
  const failed = measured.filter((m) => !m.ok);
  for (const f of failed) log('warn', 'provider measurement failed', { id: f.id, reason: f.reason });
  if (failed.length > measured.length / 2) {
    log('error', 'more than half of providers failed; refusing to overwrite data (DNS problem?)', { failed: failed.length });
    process.exit(1);
  }
  const data = mergeHistory(previous, measured, today);
  writeFileSync(DATA_FILE, JSON.stringify(data, null, 2) + '\n');
  writeSite(data);
  log('info', 'provider pages built', { pages: data.providers.length, failed: failed.length });
}

if (import.meta.url === `file://${process.argv[1]}`) main();
