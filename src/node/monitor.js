// Daily monitoring run: audit every subscribed domain once, then send welcome, change-alert
// and weekly-digest emails. Designed to be idempotent: a subscriber's state only advances
// after their email is accepted, so a failed or capped run simply retries next time.
import { auditDomain, fingerprint, suggestSpf } from '../../web/core/audit.js';
import { normalizeDomain, isValidDomain } from '../../web/core/dns.js';
import { maskEmail } from './log.js';

const DAY = 86400000;
const hash = (str) => { let h = 5381; for (let i = 0; i < str.length; i++) h = ((h << 5) + h + str.charCodeAt(i)) >>> 0; return h.toString(36); };
const TRANSIENT = new Set(['spf-dns-error', 'dmarc-dns-error', 'mx-dns-error']);

// Records that always exist. If none resolve, the resolver is broken (it can report NXDOMAIN for
// everything), and auditing would tell customers their records vanished. Abort instead.
export const CANARIES = ['_spf.google.com', 'spf.protection.outlook.com'];

export async function resolverHealthy(resolver, canaries = CANARIES) {
  for (const name of canaries) {
    const r = await resolver.resolve(name, 'TXT');
    if (r.status === 'ok' && r.records.some((x) => /^v=spf1/i.test(x))) return true;
  }
  return false;
}

export const DEFAULT_LIMITS = { maxDomains: 300, maxEmailsPerRun: 90, concurrency: 4, digestEveryDays: 7, errorAlertAfter: 3 };

function snapshot(rep) {
  return {
    grade: rep.grade, score: rep.score, lookups: rep.spf.lookups,
    spf: rep.spf.record, dmarc: rep.dmarc.record,
    dkim: rep.dkim.found.map((k) => k.selector),
    mx: rep.mx.hosts.map((h) => h.host),
    issues: rep.issues.map((i) => ({ code: i.code, severity: i.severity, area: i.area, message: i.message, fix: i.fix || null })),
  };
}

export function diffSnapshots(before, after) {
  const changes = [];
  if (before.spf !== after.spf) changes.push(`SPF record changed\n  was: ${before.spf || '(none)'}\n  now: ${after.spf || '(none)'}`);
  if (before.lookups !== after.lookups) changes.push(`SPF DNS lookups: ${before.lookups} -> ${after.lookups} (limit 10)`);
  if (before.dmarc !== after.dmarc) changes.push(`DMARC record changed\n  was: ${before.dmarc || '(none)'}\n  now: ${after.dmarc || '(none)'}`);
  const gone = before.dkim.filter((s) => !after.dkim.includes(s));
  const added = after.dkim.filter((s) => !before.dkim.includes(s));
  if (gone.length) changes.push(`DKIM key no longer found at selector(s): ${gone.join(', ')}`);
  if (added.length) changes.push(`New DKIM key found at selector(s): ${added.join(', ')}`);
  if (before.mx.join() !== after.mx.join()) changes.push(`MX records changed: ${before.mx.join(', ') || '(none)'} -> ${after.mx.join(', ') || '(none)'}`);
  const beforeCodes = new Set(before.issues.map((i) => i.code));
  const afterCodes = new Set(after.issues.map((i) => i.code));
  const newIssues = after.issues.filter((i) => !beforeCodes.has(i.code));
  const resolved = before.issues.filter((i) => !afterCodes.has(i.code));
  return { changes, newIssues, resolved, worse: after.score < before.score };
}

function issuesText(issues) {
  return issues.map((i) => `- [${i.severity.toUpperCase()}] ${i.area}: ${i.message}${i.fix ? `\n  Fix: ${i.fix}` : ''}`).join('\n');
}

function footer(ctx, domain) {
  return `\n\nFull report: ${ctx.siteUrl}/?d=${encodeURIComponent(domain)}\nManage or cancel your subscription: ${ctx.portalUrl}\n\nMailAuth Watch checks public DNS once a day. Results are guidance, not a guarantee of inbox placement.`;
}

export function welcomeEmail(ctx, domain, snap, suggested) {
  const subject = `Now watching ${domain} (grade ${snap.grade})`;
  const text = `MailAuth Watch is now checking ${domain} every day. You'll get an email when anything changes, plus a short weekly status.\n\nToday: grade ${snap.grade} (${snap.score}/100), SPF uses ${snap.lookups} of 10 DNS lookups.\n\n${snap.issues.length ? `What to fix:\n${issuesText(snap.issues)}` : 'No problems found.'}${suggested && suggested !== snap.spf ? `\n\nSuggested SPF record:\n${suggested}` : ''}${footer(ctx, domain)}`;
  return { subject, text };
}

export function alertEmail(ctx, domain, before, after, diff) {
  const subject = diff.worse || diff.newIssues.some((i) => i.severity === 'critical')
    ? `Action needed: email authentication changed on ${domain} (grade ${before.grade} -> ${after.grade})`
    : `Change detected on ${domain} (grade ${after.grade})`;
  const parts = [`We detected a change in ${domain}'s email authentication since our last email.`];
  if (diff.changes.length) parts.push(`What changed:\n${diff.changes.map((c) => `- ${c}`).join('\n')}`);
  if (diff.newIssues.length) parts.push(`New problems:\n${issuesText(diff.newIssues)}`);
  if (diff.resolved.length) parts.push(`Resolved:\n${diff.resolved.map((i) => `- ${i.area}: ${i.message}`).join('\n')}`);
  parts.push(`If you made this change on purpose and the grade is what you expect, no action is needed.`);
  return { subject, text: parts.join('\n\n') + footer(ctx, domain) };
}

export function digestEmail(ctx, domain, snap) {
  const subject = `Weekly: ${domain} is grade ${snap.grade}`;
  const text = `Weekly status for ${domain}: grade ${snap.grade} (${snap.score}/100), SPF ${snap.lookups}/10 lookups, DMARC ${snap.dmarc ? 'present' : 'missing'}, DKIM selectors found: ${snap.dkim.join(', ') || 'none'}.\n\n${snap.issues.filter((i) => i.severity !== 'info').length ? `Open items:\n${issuesText(snap.issues.filter((i) => i.severity !== 'info'))}` : 'Nothing needs attention.'}${footer(ctx, domain)}`;
  return { subject, text };
}

async function mapLimit(items, n, fn) {
  const out = new Array(items.length);
  let i = 0;
  await Promise.all(Array.from({ length: Math.min(n, items.length) }, async () => {
    while (i < items.length) { const k = i++; out[k] = await fn(items[k]); }
  }));
  return out;
}

/**
 * @param subscribers [{ subscriptionId, email, domain }]
 * @param state previous state ({ domains: {}, subs: {} })
 * @returns { state, summary, events }
 */
export async function runMonitor({ subscribers, state, resolver, mailer, ctx, now = () => new Date(), limits = {} }) {
  const L = { ...DEFAULT_LIMITS, ...limits };
  const events = [];
  const ev = (level, msg, data = {}) => events.push({ level, msg, ...data });
  const st = { domains: { ...(state?.domains || {}) }, subs: { ...(state?.subs || {}) } };
  const nowMs = now().getTime();

  if (!(await resolverHealthy(resolver, limits.canaries))) {
    ev('error', 'DNS resolver failed its health check; aborting run without changing state or sending email');
    return { state: st, events, summary: { ranAt: now().toISOString(), aborted: 'dns-canary', subscribers: subscribers.length, validSubscribers: 0, domainsChecked: 0, domainsErrored: 0, emails: { welcome: 0, alert: 0, digest: 0, failed: 0 }, deferred: 0, needsHuman: 0, errors: 1 } };
  }

  // 1. Validate subscribers; drop state for subscriptions that ended (no PII kept after cancel).
  const valid = [];
  const activeIds = new Set();
  for (const s of subscribers) {
    activeIds.add(s.subscriptionId);
    const domain = normalizeDomain(s.domain);
    if (!s.email || !isValidDomain(domain)) {
      ev('warn', 'subscriber needs attention: missing email or invalid domain', { sub: s.subscriptionId, domain: String(s.domain || '').slice(0, 80), needsHuman: true });
      continue;
    }
    valid.push({ ...s, domain });
  }
  for (const id of Object.keys(st.subs)) if (!activeIds.has(id)) { delete st.subs[id]; ev('info', 'subscription ended; state removed', { sub: id }); }

  // 2. Audit each distinct domain once, within the domain cap.
  let domains = [...new Set(valid.map((s) => s.domain))];
  if (domains.length > L.maxDomains) {
    ev('error', 'domain cap reached; extra domains skipped this run', { cap: L.maxDomains, total: domains.length });
    domains = domains.slice(0, L.maxDomains);
  }
  const reports = new Map();
  await mapLimit(domains, L.concurrency, async (d) => {
    try {
      const rep = await auditDomain(d, resolver, { now });
      const transient = rep.issues.some((i) => TRANSIENT.has(i.code));
      const prev = st.domains[d] || {};
      if (transient) {
        st.domains[d] = { ...prev, consecutiveErrors: (prev.consecutiveErrors || 0) + 1, lastErrorAt: now().toISOString() };
        ev(st.domains[d].consecutiveErrors >= L.errorAlertAfter ? 'error' : 'warn', 'DNS errors while checking domain; not alerting customer', { domain: d, consecutive: st.domains[d].consecutiveErrors });
        return;
      }
      st.domains[d] = { fp: fingerprint(rep), snapshot: snapshot(rep), suggestedSpf: suggestSpf(rep), checkedAt: rep.checkedAt, consecutiveErrors: 0 };
      reports.set(d, rep);
    } catch (e) {
      ev('error', 'audit crashed', { domain: d, error: String(e?.message || e) });
    }
  });
  for (const d of Object.keys(st.domains)) if (!domains.includes(d)) delete st.domains[d];

  // 3. Decide and send emails, within the per-run email cap.
  let sent = 0; let deferred = 0;
  const counts = { welcome: 0, alert: 0, digest: 0, failed: 0 };
  for (const s of valid) {
    const dom = st.domains[s.domain];
    if (!reports.has(s.domain) || !dom?.snapshot) continue; // not checked successfully this run
    const sub = st.subs[s.subscriptionId] || { domain: s.domain };
    if (sub.domain !== s.domain) { sub.domain = s.domain; sub.welcomedAt = null; }
    let msg = null; let kind = null;
    if (!sub.welcomedAt) { kind = 'welcome'; msg = welcomeEmail(ctx, s.domain, dom.snapshot, dom.suggestedSpf); }
    else if (sub.notifiedFp !== dom.fp) {
      const diff = diffSnapshots(sub.notifiedSnapshot, dom.snapshot);
      kind = 'alert'; msg = alertEmail(ctx, s.domain, sub.notifiedSnapshot, dom.snapshot, diff);
    } else if (nowMs - new Date(sub.lastDigestAt || sub.welcomedAt).getTime() >= L.digestEveryDays * DAY) {
      kind = 'digest'; msg = digestEmail(ctx, s.domain, dom.snapshot);
    }
    if (!msg) { st.subs[s.subscriptionId] = sub; continue; }
    if (sent >= L.maxEmailsPerRun) { deferred++; st.subs[s.subscriptionId] = sub; continue; }
    const res = await mailer.send({ to: s.email, ...msg, idempotencyKey: `${s.subscriptionId}-${kind}-${hash(dom.fp)}-${now().toISOString().slice(0, 10)}` });
    sent++;
    if (!res.ok) { counts.failed++; ev('error', 'email send failed', { sub: s.subscriptionId, to: maskEmail(s.email), kind, error: res.error }); st.subs[s.subscriptionId] = sub; continue; }
    counts[kind]++;
    const iso = now().toISOString();
    if (kind === 'welcome') { sub.welcomedAt = iso; sub.lastDigestAt = iso; }
    if (kind === 'digest') sub.lastDigestAt = iso;
    sub.notifiedFp = dom.fp; sub.notifiedSnapshot = dom.snapshot;
    st.subs[s.subscriptionId] = sub;
    ev('info', 'email sent', { sub: s.subscriptionId, to: maskEmail(s.email), kind });
  }
  if (deferred) ev('warn', 'email cap reached; remaining emails deferred to next run', { cap: L.maxEmailsPerRun, deferred });

  const summary = {
    ranAt: now().toISOString(), subscribers: subscribers.length, validSubscribers: valid.length,
    domainsChecked: reports.size, domainsErrored: domains.length - reports.size, emails: counts, deferred,
    needsHuman: events.filter((e) => e.needsHuman).length, errors: events.filter((e) => e.level === 'error').length,
  };
  return { state: st, summary, events };
}
