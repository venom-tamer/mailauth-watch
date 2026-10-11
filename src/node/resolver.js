// Node resolver using the system DNS (used by scheduled jobs on GitHub Actions).
import { promises as dns } from 'node:dns';

export function createNodeResolver({ servers, timeoutMs = 5000 } = {}) {
  const r = new dns.Resolver({ timeout: timeoutMs, tries: 2 });
  if (servers?.length) r.setServers(servers);
  const cache = new Map();
  async function uncached(name, type) {
    try {
      if (type === 'TXT') return { status: 'ok', records: (await r.resolveTxt(name)).map((chunks) => chunks.join('')) };
      if (type === 'MX') return { status: 'ok', records: (await r.resolveMx(name)).map((m) => `${m.priority} ${m.exchange.replace(/\.$/, '')}`) };
      if (type === 'A') return { status: 'ok', records: await r.resolve4(name) };
      throw new Error(`unsupported type ${type}`);
    } catch (e) {
      if (e.code === 'ENOTFOUND') return { status: 'nxdomain', records: [] };
      if (e.code === 'ENODATA') return { status: 'nodata', records: [] };
      return { status: 'error', records: [], error: e.code || e.message };
    }
  }
  return {
    resolve(name, type) {
      const key = `${type}:${name.toLowerCase()}`;
      if (!cache.has(key)) cache.set(key, uncached(name, type));
      return cache.get(key);
    },
  };
}
