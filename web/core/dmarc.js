// DMARC (RFC 7489) lookup and policy checks.

// Common multi-label public suffixes. Not the full Public Suffix List: good enough to
// find the organisational domain for the DMARC fallback lookup in most real cases.
const MULTI_SUFFIXES = new Set([
  'co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'me.uk', 'ltd.uk', 'plc.uk', 'net.uk',
  'com.au', 'net.au', 'org.au', 'edu.au', 'gov.au', 'co.nz', 'org.nz', 'net.nz',
  'com.eg', 'org.eg', 'net.eg', 'edu.eg', 'gov.eg', 'eun.eg',
  'com.br', 'net.br', 'org.br', 'com.mx', 'com.ar', 'com.tr', 'com.sa', 'com.cn', 'com.hk', 'com.sg', 'com.my',
  'co.jp', 'co.kr', 'co.in', 'net.in', 'org.in', 'co.za', 'co.il', 'com.ng', 'co.ke', 'com.pk', 'com.ph', 'com.vn',
  'ae.org', 'co.id', 'com.tw', 'com.ua', 'com.pl', 'com.es', 'com.co', 'com.pe',
]);

export function organizationalDomain(domain) {
  const labels = domain.split('.');
  if (labels.length <= 2) return domain;
  const last2 = labels.slice(-2).join('.');
  return MULTI_SUFFIXES.has(last2) ? labels.slice(-3).join('.') : last2;
}

export function parseDmarc(record) {
  const tags = {};
  for (const part of record.split(';')) {
    const [k, ...rest] = part.split('=');
    if (!k || !rest.length) continue;
    tags[k.trim().toLowerCase()] = rest.join('=').trim();
  }
  return tags;
}

export async function analyzeDmarc(domain, resolver) {
  const issues = [];
  const add = (severity, code, message, extra = {}) => issues.push({ area: 'DMARC', severity, code, message, ...extra });
  const result = { domain, record: null, source: null, tags: {}, issues };

  let lookupDomain = domain;
  let res = await resolver.resolve(`_dmarc.${domain}`, 'TXT');
  let recs = res.records.filter((r) => /^v=DMARC1\s*(;|$)/i.test(r.trim()));
  const org = organizationalDomain(domain);
  if (!recs.length && res.status !== 'error' && org !== domain) {
    lookupDomain = org;
    res = await resolver.resolve(`_dmarc.${org}`, 'TXT');
    recs = res.records.filter((r) => /^v=DMARC1\s*(;|$)/i.test(r.trim()));
  }
  if (res.status === 'error') {
    add('warning', 'dmarc-dns-error', `Could not look up DMARC (${res.error || 'DNS error'}).`);
    return result;
  }
  if (!recs.length) {
    add('critical', 'dmarc-missing', `${domain} has no DMARC record. Gmail and Yahoo (since 2024) and Outlook.com (since 2025) require DMARC from bulk senders, and a missing record lets anyone spoof your domain unchecked.`, {
      fix: `Publish TXT at _dmarc.${org}: v=DMARC1; p=none; rua=mailto:dmarc-reports@${org}  (create that mailbox first, then move to p=quarantine once reports look clean).`,
    });
    return result;
  }
  if (recs.length > 1) {
    add('critical', 'dmarc-multiple', `There are ${recs.length} DMARC records at _dmarc.${lookupDomain}. Receivers ignore DMARC entirely when there is more than one.`, { fix: 'Delete all but one.' });
  }
  result.record = recs[0];
  result.source = `_dmarc.${lookupDomain}`;
  const tags = parseDmarc(recs[0]);
  result.tags = tags;
  const p = (lookupDomain !== domain && tags.sp ? tags.sp : tags.p || '').toLowerCase();
  if (!tags.p) {
    add('critical', 'dmarc-no-policy', 'Your DMARC record has no p= tag, so it is invalid.', { fix: 'Add p=none (monitoring) or p=quarantine.' });
  } else if (!['none', 'quarantine', 'reject'].includes(p)) {
    add('critical', 'dmarc-bad-policy', `DMARC policy "${p}" is not valid.`, { fix: 'Use none, quarantine or reject.' });
  } else if (p === 'none') {
    add('warning', 'dmarc-p-none', 'DMARC is in monitoring mode (p=none): spoofed mail using your domain is still delivered.', { fix: 'Once your reports show only legitimate senders passing, move to p=quarantine, then p=reject.' });
  }
  if (tags.pct && Number(tags.pct) < 100 && p !== 'none') {
    add('info', 'dmarc-pct', `Only ${tags.pct}% of failing mail is subject to your policy (pct=${tags.pct}).`, { fix: 'Raise pct to 100 when ready.' });
  }
  if (!tags.rua) {
    add('warning', 'dmarc-no-rua', 'No aggregate report address (rua=), so you cannot see who is sending mail as your domain.', { fix: `Add rua=mailto:dmarc-reports@${org}` });
  } else {
    const bad = tags.rua.split(',').map((s) => s.trim()).filter((u) => !/^mailto:[^@\s]+@[^@\s]+$/i.test(u.replace(/!\d+[kmgt]?$/i, '')));
    if (bad.length) add('warning', 'dmarc-bad-rua', `rua contains invalid entries: ${bad.join(', ')}`, { fix: 'Each rua entry must be mailto:address@domain.' });
  }
  return result;
}
