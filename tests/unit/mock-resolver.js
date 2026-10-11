// In-memory resolver for tests. zone: { 'TXT example.com': ['v=spf1 ...'], 'MX example.com': ['10 mx.example.com'] }
// Names absent from the zone return nxdomain; `errors` lists names that simulate DNS failures.
export function mockResolver(zone, { errors = [] } = {}) {
  const calls = [];
  return {
    calls,
    async resolve(name, type) {
      const key = `${type} ${name.toLowerCase()}`;
      calls.push(key);
      if (errors.includes(key)) return { status: 'error', records: [], error: 'SERVFAIL' };
      if (!(key in zone)) return { status: 'nxdomain', records: [] };
      const records = zone[key];
      return { status: records.length ? 'ok' : 'nodata', records };
    },
  };
}
