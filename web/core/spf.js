// SPF analysis per RFC 7208, focused on what breaks delivery in practice:
// the 10 DNS-lookup limit, the 2 void-lookup limit, multiple records, and weak or
// dangerous `all` qualifiers. Pure ESM: works in the browser and in Node.

export const SPF_LOOKUP_LIMIT = 10;
export const SPF_VOID_LIMIT = 2;
const MAX_DEPTH = 12;

export function selectSpfRecords(txtRecords) {
  return (txtRecords || []).filter((r) => /^v=spf1(\s|$)/i.test(r.trim()));
}

/** Split an SPF record into terms: { qualifier, name, value, raw, kind: 'mechanism' | 'modifier' | 'unknown' }. */
export function parseSpf(record) {
  const tokens = record.trim().split(/\s+/).slice(1);
  return tokens.map((raw) => {
    const mod = raw.match(/^([a-z][a-z0-9_.-]*)=(.*)$/i);
    if (mod) return { kind: 'modifier', name: mod[1].toLowerCase(), value: mod[2], raw, qualifier: '' };
    const m = raw.match(/^([+\-~?]?)([a-z0-9]+)(?:[:/](.*))?$/i);
    if (!m) return { kind: 'unknown', name: raw, value: '', raw, qualifier: '' };
    const name = m[2].toLowerCase();
    let value = m[3] || '';
    // a/24 and mx/24 forms: keep CIDR out of the domain part
    if (raw.slice(m[1].length + m[2].length).startsWith('/')) value = '';
    else value = value.split('/')[0];
    const known = ['all', 'include', 'a', 'mx', 'ptr', 'ip4', 'ip6', 'exists'];
    return { kind: known.includes(name) ? 'mechanism' : 'unknown', qualifier: m[1] || '+', name, value, raw };
  });
}

const hasMacro = (s) => /%\{/.test(s || '');

/**
 * Walk the full SPF include tree for `domain` and count DNS lookups.
 * Counts the worst case (every branch evaluated), which is what decides
 * whether some receivers will return permerror.
 */
export async function analyzeSpf(domain, resolver) {
  const issues = [];
  const counters = { lookups: 0, voids: 0, queries: 0 };
  const add = (severity, code, message, extra = {}) => issues.push({ area: 'SPF', severity, code, message, ...extra });

  async function walk(target, depth, stack, viaTerm) {
    const node = { domain: target, via: viaTerm || null, record: null, terms: [], children: [], selfLookups: 0, status: 'ok' };
    if (depth > MAX_DEPTH) { node.status = 'too-deep'; return node; }
    if (stack.includes(target)) {
      node.status = 'loop';
      add('critical', 'spf-loop', `SPF include loop detected at ${target}.`);
      return node;
    }
    counters.queries++;
    const res = await resolver.resolve(target, 'TXT');
    if (res.status === 'error') {
      node.status = 'dns-error';
      add('warning', 'spf-dns-error', `Could not look up SPF for ${target} (${res.error || 'DNS error'}). Results may be incomplete.`);
      return node;
    }
    const spf = selectSpfRecords(res.records);
    if (spf.length === 0) {
      node.status = 'none';
      if (depth > 0) {
        counters.voids += res.status === 'ok' ? 0 : 1;
        add('critical', 'spf-include-missing', `${target} is referenced by your SPF but publishes no SPF record. Receivers treat this as a permanent error.`, { target, fix: `Remove "${viaTerm}" or correct the domain name.` });
      }
      return node;
    }
    if (spf.length > 1) {
      node.status = 'multiple';
      add('critical', 'spf-multiple', `${target} publishes ${spf.length} SPF records. Only one is allowed; receivers return permerror.`, { fix: 'Merge them into a single v=spf1 record.' });
    }
    node.record = spf[0];
    node.terms = parseSpf(spf[0]);
    const hasAll = node.terms.some((t) => t.kind === 'mechanism' && t.name === 'all');

    for (const t of node.terms) {
      if (t.kind === 'unknown') {
        add('critical', 'spf-syntax', `Unrecognised term "${t.raw}" in SPF for ${target}. This is a syntax error (permerror).`, { fix: `Remove or correct "${t.raw}".` });
        continue;
      }
      if (t.kind === 'modifier' && t.name === 'redirect') {
        if (hasAll) continue; // redirect is ignored when `all` is present
        node.selfLookups++; counters.lookups++;
        if (hasMacro(t.value)) continue;
        node.children.push(await walk(t.value.toLowerCase(), depth + 1, [...stack, target], t.raw));
        continue;
      }
      if (t.kind !== 'mechanism') continue;
      switch (t.name) {
        case 'include':
          node.selfLookups++; counters.lookups++;
          if (!t.value) { add('critical', 'spf-syntax', `"${t.raw}" has no domain.`); break; }
          if (hasMacro(t.value)) break;
          node.children.push(await walk(t.value.toLowerCase(), depth + 1, [...stack, target], t.raw));
          break;
        case 'a':
        case 'exists':
          node.selfLookups++; counters.lookups++;
          break;
        case 'ptr':
          node.selfLookups++; counters.lookups++;
          add('warning', 'spf-ptr', `"${t.raw}" in ${target} uses the ptr mechanism, which RFC 7208 says not to use. Some receivers ignore it.`, { fix: `Replace "${t.raw}" with ip4:/ip6: ranges or an include.` });
          break;
        case 'mx': {
          node.selfLookups++; counters.lookups++;
          const mxDomain = t.value && !hasMacro(t.value) ? t.value : target;
          counters.queries++;
          const mx = await resolver.resolve(mxDomain, 'MX');
          if (mx.status === 'nxdomain' || mx.status === 'nodata') counters.voids++;
          if (mx.records.length > 10) add('critical', 'spf-mx-too-many', `"${t.raw}" points at ${mx.records.length} MX hosts; SPF allows at most 10.`);
          break;
        }
        default:
          break;
      }
    }
    return node;
  }

  const tree = await walk(domain, 0, [], null);
  const result = { domain, tree, record: tree.record, lookups: counters.lookups, voidLookups: counters.voids, queries: counters.queries, issues };

  if (tree.status === 'none') {
    add('critical', 'spf-missing', `${domain} has no SPF record. Gmail, Yahoo and Outlook expect SPF or DKIM on every message, and SPF plus DKIM plus DMARC for bulk senders.`, { fix: 'Publish a v=spf1 TXT record that lists every service that sends mail as your domain.' });
    return result;
  }
  if (!tree.record) return result;

  if (counters.lookups > SPF_LOOKUP_LIMIT) {
    add('critical', 'spf-too-many-lookups', `Your SPF needs ${counters.lookups} DNS lookups; the limit is ${SPF_LOOKUP_LIMIT}. Receivers that evaluate past the limit return permerror and SPF fails.`, { fix: 'Remove includes for services you no longer use, move some senders to a subdomain, or replace includes with the ip4:/ip6: ranges they resolve to (and monitor them for changes).' });
  } else if (counters.lookups >= SPF_LOOKUP_LIMIT - 1) {
    add('warning', 'spf-near-limit', `Your SPF uses ${counters.lookups} of ${SPF_LOOKUP_LIMIT} DNS lookups. One more include, or a provider changing theirs, will break it.`, { fix: 'Remove unused includes now, and watch for provider changes.' });
  }
  if (counters.voids > SPF_VOID_LIMIT) {
    add('critical', 'spf-void-lookups', `Your SPF triggers ${counters.voids} lookups that return nothing; more than ${SPF_VOID_LIMIT} is a permerror.`);
  }

  const terms = tree.terms;
  const all = terms.find((t) => t.kind === 'mechanism' && t.name === 'all');
  const redirect = terms.find((t) => t.kind === 'modifier' && t.name === 'redirect');
  if (!all && !redirect) {
    add('warning', 'spf-no-all', 'Your SPF has no "all" mechanism, so mail from anywhere else gets a neutral result instead of failing.', { fix: 'End the record with ~all (or -all once you are sure every sender is listed).' });
  } else if (all) {
    if (all.qualifier === '+') add('critical', 'spf-plus-all', 'Your SPF ends in +all, which authorises every server on the internet to send as you.', { fix: 'Change +all to ~all.' });
    if (all.qualifier === '?') add('warning', 'spf-neutral-all', 'Your SPF ends in ?all (neutral), which gives receivers no guidance about unlisted senders.', { fix: 'Change ?all to ~all.' });
    const idx = terms.indexOf(all);
    if (idx !== terms.length - 1 && terms.slice(idx + 1).some((t) => t.kind === 'mechanism')) {
      add('warning', 'spf-after-all', 'Mechanisms after "all" are never evaluated.', { fix: 'Move "all" to the end of the record.' });
    }
  }
  if (new TextEncoder().encode(tree.record).length > 450) {
    add('info', 'spf-long', 'Your SPF record is long; very long TXT answers can be truncated over UDP by some resolvers.');
  }
  return result;
}

/** Flatten the include tree into a list of { domain, depth, selfLookups, record } rows for display. */
export function flattenTree(node, depth = 0, out = []) {
  out.push({ domain: node.domain, depth, selfLookups: node.selfLookups, record: node.record, status: node.status, via: node.via });
  for (const c of node.children) flattenTree(c, depth + 1, out);
  return out;
}

/** Total lookups spent by a subtree, including the reference to it. */
export function subtreeLookups(node) {
  return node.selfLookups + node.children.reduce((s, c) => s + subtreeLookups(c), 0);
}
