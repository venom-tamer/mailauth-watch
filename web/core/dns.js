// Shared DNS helpers. Runs unchanged in the browser and in Node.
//
// A resolver is any object with `resolve(name, type)` returning
// Promise<{ status: 'ok' | 'nxdomain' | 'nodata' | 'error', records: string[], error?: string }>
// TXT records come back with their character-strings already joined.
// MX records come back as "<preference> <host>" with the trailing dot removed.

const TYPE_CODES = { A: 1, CNAME: 5, MX: 15, TXT: 16, AAAA: 28 };

/** Join the quoted character-strings of a DoH TXT `data` field into one string. */
export function joinTxtData(data) {
  const s = String(data).trim();
  if (!s.startsWith('"')) return s;
  const parts = [];
  let i = 0;
  while (i < s.length) {
    if (s[i] !== '"') { i++; continue; }
    i++;
    let buf = '';
    while (i < s.length && s[i] !== '"') {
      if (s[i] === '\\' && i + 1 < s.length) {
        // DNS presentation format escapes: \" \\ and \DDD (decimal byte)
        const d = s.slice(i + 1, i + 4);
        if (/^\d{3}$/.test(d)) { buf += String.fromCharCode(parseInt(d, 10)); i += 4; continue; }
        buf += s[i + 1]; i += 2; continue;
      }
      buf += s[i++];
    }
    parts.push(buf);
    i++;
  }
  return parts.join('');
}

export function normalizeDomain(input) {
  let d = String(input || '').trim().toLowerCase();
  d = d.replace(/^[a-z]+:\/\//, '');      // strip scheme if a URL was pasted
  d = d.replace(/^[^@]*@/, '');           // strip local part if an email was pasted
  d = d.split(/[/?#:]/)[0];               // strip path, query, port
  d = d.replace(/\.$/, '');
  if (d.startsWith('www.')) d = d.slice(4);
  return d;
}

export function isValidDomain(d) {
  if (!d || d.length > 253) return false;
  const labels = d.split('.');
  if (labels.length < 2) return false;
  return labels.every((l) => /^[a-z0-9_](?:[a-z0-9-_]{0,61}[a-z0-9])?$/.test(l)) && /[a-z]/.test(labels[labels.length - 1]);
}

/**
 * DNS-over-HTTPS resolver using the JSON API offered by Cloudflare and Google.
 * Both send CORS headers, so this works from a static web page with no backend.
 */
export function createDohResolver({ endpoints, fetchImpl, timeoutMs = 6000 } = {}) {
  const urls = endpoints || ['https://cloudflare-dns.com/dns-query', 'https://dns.google/resolve'];
  const f = fetchImpl || ((...a) => fetch(...a));
  const cache = new Map();

  async function query(base, name, type) {
    const ctrl = typeof AbortController !== 'undefined' ? new AbortController() : null;
    const timer = ctrl ? setTimeout(() => ctrl.abort(), timeoutMs) : null;
    try {
      const url = `${base}?name=${encodeURIComponent(name)}&type=${type}`;
      const res = await f(url, { headers: { accept: 'application/dns-json' }, signal: ctrl?.signal });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      return await res.json();
    } finally {
      if (timer) clearTimeout(timer);
    }
  }

  async function resolveUncached(name, type) {
    let lastErr;
    for (const base of urls) {
      try {
        const j = await query(base, name, type);
        if (j.Status === 3) return { status: 'nxdomain', records: [] };
        if (j.Status !== 0) return { status: 'error', records: [], error: `DNS status ${j.Status}` };
        const code = TYPE_CODES[type];
        const answers = (j.Answer || []).filter((a) => a.type === code);
        if (!answers.length) return { status: 'nodata', records: [] };
        const records = answers.map((a) => {
          if (type === 'TXT') return joinTxtData(a.data);
          if (type === 'MX') return String(a.data).replace(/\.$/, '');
          return String(a.data).replace(/\.$/, '');
        });
        return { status: 'ok', records };
      } catch (e) {
        lastErr = e;
      }
    }
    return { status: 'error', records: [], error: String(lastErr?.message || lastErr) };
  }

  return {
    async resolve(name, type) {
      const key = `${type}:${name.toLowerCase()}`;
      if (!cache.has(key)) cache.set(key, resolveUncached(name, type));
      return cache.get(key);
    },
  };
}
