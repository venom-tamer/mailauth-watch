// Minimal Polar API client (https://polar.sh/docs/api-reference). Token comes from the
// POLAR_ACCESS_TOKEN env var (an Organization Access Token with subscriptions:read and orders:read).
const ACTIVE = new Set(['active', 'trialing']);

export function polarBase(env = process.env) {
  return env.POLAR_SERVER === 'production' ? 'https://api.polar.sh' : 'https://sandbox-api.polar.sh';
}

async function getAll(path, { token, baseUrl, fetchImpl = fetch, maxPages = 50, params = {} }) {
  const items = [];
  for (let page = 1; page <= maxPages; page++) {
    const qs = new URLSearchParams({ ...params, page: String(page), limit: '100' });
    const res = await fetchImpl(`${baseUrl}${path}?${qs}`, { headers: { authorization: `Bearer ${token}`, accept: 'application/json' } });
    if (!res.ok) throw new Error(`Polar ${path} HTTP ${res.status}`);
    const j = await res.json();
    items.push(...(j.items || []));
    if (page >= (j.pagination?.max_page || 1)) break;
  }
  return items;
}

/** Active subscribers as [{ subscriptionId, email, domain, productId, startedAt }]. */
export async function listActiveSubscribers(opts) {
  const field = opts.domainField || 'domain';
  const subs = await getAll('/v1/subscriptions/', opts);
  return subs.filter((s) => ACTIVE.has(s.status)).map((s) => ({
    subscriptionId: s.id,
    email: s.customer?.email || null,
    domain: s.custom_field_data?.[field] ?? null,
    productId: s.product_id || s.product?.id || null,
    startedAt: s.started_at || s.created_at || null,
  }));
}

/** Paid orders created on or after `since` (ISO date). Amounts stay in cents. */
export async function listOrders(opts, since) {
  const orders = await getAll('/v1/orders/', { ...opts, params: since ? { created_after: since } : {} });
  return orders.map((o) => ({
    id: o.id, createdAt: o.created_at, status: o.status, currency: o.currency,
    netAmount: o.net_amount, totalAmount: o.total_amount, taxAmount: o.tax_amount, billingReason: o.billing_reason,
  }));
}
