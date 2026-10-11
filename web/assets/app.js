import config from './config.js';
import { auditDomain, suggestSpf } from '../core/audit.js';
import { createDohResolver, normalizeDomain, isValidDomain } from '../core/dns.js';
import { flattenTree, subtreeLookups, SPF_LOOKUP_LIMIT } from '../core/spf.js';

const $ = (sel) => document.querySelector(sel);
const form = $('#check-form');
const input = $('#domain');
const btn = $('#check-btn');
const errEl = $('#form-error');
const out = $('#results');

// --- analytics (optional, privacy-friendly; only loads when configured) ---
function track(name, data) {
  try { window.umami?.track(name, data); } catch { /* analytics must never break the page */ }
}
if (config.analytics?.umamiWebsiteId && config.analytics?.umamiSrc) {
  const s = document.createElement('script');
  s.defer = true; s.src = config.analytics.umamiSrc; s.dataset.websiteId = config.analytics.umamiWebsiteId;
  document.head.appendChild(s);
}

// --- checkout CTA ---
function checkoutHref(source) {
  if (!config.checkoutUrl) return null;
  const u = new URL(config.checkoutUrl);
  u.searchParams.set('utm_source', 'mailauth-watch');
  u.searchParams.set('utm_content', source);
  return u.toString();
}
function wireCta(a) {
  const href = checkoutHref(a.dataset.cta || 'unknown');
  if (href) {
    a.href = href; a.rel = 'noopener';
  } else {
    a.removeAttribute('href'); a.setAttribute('aria-disabled', 'true'); a.textContent = 'Monitoring opens soon';
    const note = a.parentElement.querySelector('#cta-note');
    if (note) { note.hidden = false; note.textContent = 'Checkout is not live yet. The free checker works now.'; }
  }
  a.addEventListener('click', () => track('cta_click', { source: a.dataset.cta, enabled: Boolean(href) }));
}
document.querySelectorAll('[data-price]').forEach((el) => { el.textContent = config.priceLabel || el.textContent; });
document.querySelectorAll('[data-cta]').forEach(wireCta);

// --- DOM helpers (textContent only: DNS data is untrusted) ---
function h(tag, attrs = {}, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v === false || v == null) continue;
    if (k === 'class') el.className = v; else if (k.startsWith('on')) el.addEventListener(k.slice(2), v); else el.setAttribute(k, v);
  }
  for (const kid of kids.flat()) if (kid != null && kid !== false) el.append(kid instanceof Node ? kid : document.createTextNode(String(kid)));
  return el;
}
function copyButton(text) {
  return h('button', { type: 'button', class: 'copy', onclick: async (e) => {
    try { await navigator.clipboard.writeText(text); e.target.textContent = 'Copied'; } catch { e.target.textContent = 'Select and copy manually'; }
    setTimeout(() => { e.target.textContent = 'Copy'; }, 1500);
  } }, 'Copy');
}
function recordBlock(text) { return h('div', {}, h('div', { class: 'record' }, text), copyButton(text)); }

function render(rep) {
  out.replaceChildren();
  const summaryText = rep.counts.critical ? `${rep.counts.critical} critical problem${rep.counts.critical > 1 ? 's' : ''} to fix` : rep.counts.warning ? `${rep.counts.warning} thing${rep.counts.warning > 1 ? 's' : ''} to improve` : 'No problems found';
  out.append(h('div', { class: 'summary' },
    h('div', { class: `grade ${rep.grade}`, 'aria-label': `Grade ${rep.grade}` }, rep.grade),
    h('div', {},
      h('h2', {}, rep.domain),
      h('div', {}, `Score ${rep.score}/100 · ${summaryText}`),
      rep.providers.length ? h('div', { class: 'chips' }, rep.providers.map((p) => h('span', { class: 'chip' }, p.name))) : null,
    ),
  ));

  if (rep.issues.length) {
    out.append(h('h3', {}, 'What to fix'));
    for (const i of rep.issues) {
      out.append(h('div', { class: `issue ${i.severity}` },
        h('div', {}, h('span', { class: `sev ${i.severity}` }, i.severity), h('strong', {}, i.area)),
        h('p', {}, i.message),
        i.fix ? h('p', { class: 'fix' }, 'Fix: ', i.fix) : null,
      ));
    }
  }

  // SPF lookup budget
  const used = rep.spf.lookups;
  const pct = Math.min(100, (used / SPF_LOOKUP_LIMIT) * 100);
  const spfCard = h('div', { class: 'card' }, h('h3', {}, `SPF lookups: ${used} of ${SPF_LOOKUP_LIMIT}`));
  spfCard.append(h('div', { class: `meter ${used > SPF_LOOKUP_LIMIT ? 'over' : used >= 9 ? 'near' : ''}`, role: 'img', 'aria-label': `${used} of ${SPF_LOOKUP_LIMIT} lookups used` }, h('span', { style: `width:${pct}%` })));
  if (rep.spf.record) {
    const rows = flattenTree(rep.spf.tree).slice(1);
    spfCard.append(h('div', { class: 'record' }, rep.spf.record));
    if (rows.length) {
      const costOf = new Map();
      (function walk(n) { costOf.set(n, subtreeLookups(n)); n.children.forEach(walk); })(rep.spf.tree);
      const nodes = []; (function walk(n, d) { if (d) nodes.push([n, d]); n.children.forEach((c) => walk(c, d + 1)); })(rep.spf.tree, 0);
      spfCard.append(h('ul', { class: 'tree' }, nodes.map(([n, d]) => h('li', {},
        h('span', { style: `padding-left:${(d - 1) * 16}px` }, `${d > 1 ? '└ ' : ''}${n.domain}${n.status !== 'ok' ? ` (${n.status})` : ''}`),
        h('span', { class: 'cost' }, `${costOf.get(n) + 1} lookup${costOf.get(n) ? 's' : ''}`),
      ))));
    }
  } else {
    spfCard.append(h('p', {}, 'No SPF record found.'));
  }
  const suggested = suggestSpf(rep);
  if (suggested && suggested !== rep.spf.record) spfCard.append(h('p', { class: 'fix' }, 'Suggested record:'), recordBlock(suggested));

  const dmarcCard = h('div', { class: 'card' }, h('h3', {}, 'DMARC'));
  dmarcCard.append(rep.dmarc.record ? h('div', {}, h('p', { class: 'fine' }, rep.dmarc.source), h('div', { class: 'record' }, rep.dmarc.record)) : h('p', {}, 'No DMARC record found.'));

  const dkimCard = h('div', { class: 'card' }, h('h3', {}, 'DKIM'));
  dkimCard.append(rep.dkim.found.length
    ? h('ul', {}, rep.dkim.found.map((k) => h('li', {}, `${k.selector}._domainkey: ${k.bits ? `~${k.bits}-bit key` : 'revoked'}`)))
    : h('p', {}, `No key at ${rep.dkim.checked.length} common selectors.`));

  const mxCard = h('div', { class: 'card' }, h('h3', {}, 'Mail servers (MX)'));
  mxCard.append(rep.mx.hosts.length ? h('ul', {}, rep.mx.hosts.map((m) => h('li', {}, `${m.pref} ${m.host}`))) : h('p', {}, 'No MX records.'));
  mxCard.append(h('p', { class: 'fine' }, `MTA-STS: ${rep.mtaSts ? 'yes' : 'no'} · TLS-RPT: ${rep.tlsRpt ? 'yes' : 'no'} · BIMI: ${rep.bimi ? 'yes' : 'no'}`));

  out.append(h('div', { class: 'grid2' }, spfCard, dmarcCard, dkimCard, mxCard));

  const cta = h('a', { class: 'btn', 'data-cta': 'results' }, 'Watch this domain');
  out.append(h('div', { class: 'upsell' },
    h('h3', {}, rep.counts.critical ? 'Fixed it? Make sure it stays fixed.' : 'All good today. Will it be next month?'),
    h('p', {}, `For ${config.priceLabel || '$5'}/month we re-check ${rep.domain} every day and email you when a record changes, a provider's include grows, or a key disappears.`),
    cta,
  ));
  wireCta(cta);
  out.append(h('p', { class: 'fine' }, `Checked ${new Date(rep.checkedAt).toLocaleString()}. `, h('a', { href: `?d=${encodeURIComponent(rep.domain)}` }, 'Link to this check')));
  out.hidden = false;
}

async function run(raw) {
  const domain = normalizeDomain(raw);
  errEl.hidden = true;
  if (!isValidDomain(domain)) {
    errEl.textContent = 'Enter a domain name like example.com.'; errEl.hidden = false; input.focus();
    return;
  }
  input.value = domain;
  btn.disabled = true; btn.textContent = 'Checking…';
  out.hidden = false; out.replaceChildren(h('p', {}, `Looking up DNS records for ${domain}…`));
  try {
    const rep = await auditDomain(domain, createDohResolver());
    render(rep);
    track('check', { grade: rep.grade, critical: rep.counts.critical });
    history.replaceState(null, '', `?d=${encodeURIComponent(domain)}`);
  } catch (e) {
    out.replaceChildren(h('p', { class: 'error' }, 'The check failed. Your network may block encrypted DNS lookups; try again or from another network.'));
    console.error(e);
  } finally {
    btn.disabled = false; btn.textContent = 'Check domain';
  }
}

form.addEventListener('submit', (e) => { e.preventDefault(); run(input.value); });
const initial = new URLSearchParams(location.search).get('d');
if (initial) { input.value = initial; run(initial); }
