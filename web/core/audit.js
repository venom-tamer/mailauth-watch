// Full email-authentication audit for one domain. Pure ESM, resolver injected.
import { analyzeSpf } from './spf.js';
import { analyzeDmarc, organizationalDomain } from './dmarc.js';
import { detectProviders, GENERIC_SELECTORS, PROVIDERS } from './providers.js';

export const AUDIT_VERSION = 1;
const WEIGHTS = { critical: 25, warning: 8, info: 0 };

function dkimKeyBits(record) {
  const m = record.match(/(?:^|;)\s*p=([^;]*)/i);
  if (!m) return null;
  const b64 = m[1].replace(/\s+/g, '');
  if (!b64) return 0; // revoked key
  if (/k=ed25519/i.test(record)) return 256;
  const bytes = Math.floor((b64.length * 3) / 4);
  // RSA SubjectPublicKeyInfo size is roughly modulus + ~38 bytes of overhead
  if (bytes < 100) return 512;
  if (bytes < 180) return 1024;
  if (bytes < 330) return 2048;
  return 4096;
}

async function analyzeMx(domain, resolver) {
  const res = await resolver.resolve(domain, 'MX');
  const hosts = res.records
    .map((r) => { const [pref, host] = r.split(/\s+/); return { pref: Number(pref), host: (host || '').toLowerCase() }; })
    .filter((h) => h.host)
    .sort((a, b) => a.pref - b.pref);
  const nullMx = hosts.length === 1 && (hosts[0].host === '' || hosts[0].host === '.');
  return { status: res.status, hosts, nullMx };
}

async function analyzeDkim(domain, resolver, providers) {
  const selectors = [...new Set([...providers.flatMap((p) => p.selectors), ...GENERIC_SELECTORS])].slice(0, 24);
  const found = [];
  await Promise.all(selectors.map(async (sel) => {
    const res = await resolver.resolve(`${sel}._domainkey.${domain}`, 'TXT');
    const rec = res.records.find((r) => /(^|;)\s*(v=DKIM1|p=)/i.test(r));
    if (rec) found.push({ selector: sel, record: rec, bits: dkimKeyBits(rec) });
  }));
  found.sort((a, b) => a.selector.localeCompare(b.selector));
  return { checked: selectors, found };
}

async function txtStartingWith(resolver, name, prefix) {
  const res = await resolver.resolve(name, 'TXT');
  return res.records.find((r) => r.toLowerCase().startsWith(prefix.toLowerCase())) || null;
}

export function gradeFor(score) {
  if (score >= 90) return 'A';
  if (score >= 75) return 'B';
  if (score >= 60) return 'C';
  if (score >= 40) return 'D';
  return 'F';
}

export async function auditDomain(domain, resolver, { now = () => new Date() } = {}) {
  const [spf, dmarc, mx] = await Promise.all([
    analyzeSpf(domain, resolver),
    analyzeDmarc(domain, resolver),
    analyzeMx(domain, resolver),
  ]);
  const providers = detectProviders(spf.record, mx.hosts.map((h) => h.host));
  const [dkim, mtaSts, tlsRpt, bimi] = await Promise.all([
    analyzeDkim(domain, resolver, providers),
    txtStartingWith(resolver, `_mta-sts.${domain}`, 'v=STSv1'),
    txtStartingWith(resolver, `_smtp._tls.${domain}`, 'v=TLSRPTv1'),
    txtStartingWith(resolver, `default._bimi.${domain}`, 'v=BIMI1'),
  ]);

  const issues = [...spf.issues, ...dmarc.issues];
  const add = (area, severity, code, message, extra = {}) => issues.push({ area, severity, code, message, ...extra });

  if (mx.status === 'error') add('MX', 'warning', 'mx-dns-error', 'Could not look up MX records.');
  else if (!mx.hosts.length) add('MX', 'info', 'mx-none', `${domain} has no MX records, so it cannot receive email. If it also never sends email, publish "v=spf1 -all" and a DMARC p=reject record so nobody can spoof it.`);

  if (!dkim.found.length) {
    add('DKIM', 'warning', 'dkim-not-found', `No DKIM key found at ${dkim.checked.length} common selectors. DKIM may still exist under a custom selector, but if it is missing, Gmail and Yahoo will penalise your mail.`, {
      fix: providers.length ? `Turn on DKIM signing in ${providers.map((p) => p.name).join(', ')} and publish the key they give you.` : 'Turn on DKIM signing in your email provider and publish the key it gives you.',
    });
  }
  for (const k of dkim.found) {
    if (k.bits === 0) add('DKIM', 'info', 'dkim-revoked', `DKIM selector "${k.selector}" has an empty key (revoked).`);
    else if (k.bits && k.bits < 1024) add('DKIM', 'critical', 'dkim-weak', `DKIM selector "${k.selector}" uses a key shorter than 1024 bits, which receivers reject.`, { fix: 'Rotate to a 2048-bit key.' });
    else if (k.bits === 1024) add('DKIM', 'info', 'dkim-1024', `DKIM selector "${k.selector}" uses a 1024-bit key. It works, but 2048-bit is recommended.`, { fix: 'Rotate to a 2048-bit key when convenient.' });
  }
  if (mx.hosts.length && !mtaSts) add('Transport', 'info', 'mta-sts-missing', 'No MTA-STS policy: mail sent to you can be downgraded to unencrypted transport by an attacker on the path.');
  if (mx.hosts.length && !tlsRpt) add('Transport', 'info', 'tls-rpt-missing', 'No TLS-RPT record, so you will not hear about TLS delivery failures to your domain.');

  const penalty = issues.reduce((s, i) => s + (WEIGHTS[i.severity] || 0), 0);
  const score = Math.max(0, 100 - penalty);
  const order = { critical: 0, warning: 1, info: 2 };
  issues.sort((a, b) => order[a.severity] - order[b.severity]);

  return {
    version: AUDIT_VERSION,
    domain,
    orgDomain: organizationalDomain(domain),
    checkedAt: now().toISOString(),
    score,
    grade: gradeFor(score),
    providers: providers.map((p) => ({ id: p.id, name: p.name, kind: p.kind })),
    spf: { record: spf.record, lookups: spf.lookups, voidLookups: spf.voidLookups, tree: spf.tree },
    dmarc: { record: dmarc.record, source: dmarc.source, tags: dmarc.tags },
    dkim,
    mx,
    mtaSts,
    tlsRpt,
    bimi,
    issues,
    counts: {
      critical: issues.filter((i) => i.severity === 'critical').length,
      warning: issues.filter((i) => i.severity === 'warning').length,
      info: issues.filter((i) => i.severity === 'info').length,
    },
  };
}

/** Recommended SPF record: keeps the existing record's senders but repairs dangerous or broken parts. */
export function suggestSpf(report) {
  const rec = report.spf.record;
  if (!rec) {
    const incs = report.providers
      .map((p) => PROVIDERS.find((x) => x.id === p.id)?.spf)
      .filter(Boolean)
      .map((d) => `include:${d}`);
    return incs.length ? `v=spf1 ${incs.join(' ')} ~all` : null;
  }
  let terms = rec.trim().split(/\s+/).slice(1);
  terms = terms.filter((t) => !/^[+?~-]?ptr(:|$)/i.test(t));
  terms = terms.filter((t) => !/^[+?~-]?all$/i.test(t));
  const missingInclude = new Set(report.issues.filter((i) => i.code === 'spf-include-missing').map((i) => i.target));
  terms = terms.filter((t) => !(t.toLowerCase().startsWith('include:') && missingInclude.has(t.slice(8).toLowerCase())));
  const hasRedirect = terms.some((t) => /^redirect=/i.test(t));
  // Nothing authorised would remain: a suggestion like "v=spf1 ~all" would fail all real mail.
  if (!terms.some((t) => /^([+?~-]?(include|a|mx|ip4|ip6|exists)\b|redirect=)/i.test(t))) return null;
  const oldAll = rec.match(/\s([+?~-]?)all(\s|$)/i);
  const q = oldAll && oldAll[1] === '-' ? '-' : '~';
  return `v=spf1 ${terms.join(' ')}${hasRedirect ? '' : ` ${q}all`}`.replace(/\s+/g, ' ').trim();
}

/**
 * A stable fingerprint of the security-relevant state, used by monitoring to detect changes.
 * Excludes timestamps so two identical states compare equal.
 */
export function fingerprint(report) {
  return JSON.stringify({
    spf: report.spf.record,
    lookups: report.spf.lookups,
    dmarc: report.dmarc.record,
    dkim: report.dkim.found.map((k) => `${k.selector}:${k.bits}`),
    mx: report.mx.hosts.map((h) => h.host),
    mtaSts: report.mtaSts,
    issues: report.issues.map((i) => i.code).sort(),
  });
}
