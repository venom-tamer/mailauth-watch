// Builds the weekly business report. Revenue comes only from the payment provider's API;
// when it is not connected the report says so instead of showing a number.
export function buildReport({ today, periodDays, orders, subscribers, costs, monitor, providers, polarConnected, polarMode }) {
  const since = new Date(new Date(today).getTime() - periodDays * 86400000).toISOString().slice(0, 10);
  const lines = [`# Business report ${today}`, '', `Period: ${since} to ${today} (${periodDays} days)`, ''];

  lines.push('## Revenue actually received');
  if (!polarConnected) {
    lines.push('Payment provider not connected (POLAR_ACCESS_TOKEN missing). Revenue: not measurable; none recorded.');
  } else {
    const paid = orders.filter((o) => ['paid', 'partially_refunded'].includes(o.status));
    const refunded = orders.filter((o) => o.status === 'refunded');
    const byCur = {};
    for (const o of paid) byCur[o.currency] = (byCur[o.currency] || 0) + (o.netAmount || 0);
    const label = polarMode === 'production' ? 'LIVE' : 'SANDBOX (test money, not revenue)';
    lines.push(`Source: Polar ${label}`);
    lines.push(`- Paid orders: ${paid.length}; refunded: ${refunded.length}`);
    lines.push(`- Net of discounts, before tax and Polar fees: ${Object.entries(byCur).map(([c, v]) => `${(v / 100).toFixed(2)} ${c.toUpperCase()}`).join(', ') || '0.00'}`);
    lines.push(`- New subscriptions: ${paid.filter((o) => o.billingReason === 'subscription_create').length}; renewals: ${paid.filter((o) => o.billingReason === 'subscription_cycle').length}`);
  }
  lines.push('', '## Customers');
  lines.push(polarConnected ? `- Active subscriptions: ${subscribers.length}` : '- Active subscriptions: unknown (provider not connected)');

  lines.push('', '## Expenses actually incurred');
  const periodCosts = costs.filter((c) => c.date >= since && c.date <= today);
  const total = costs.reduce((s, c) => s + c.amountUsd, 0);
  lines.push(periodCosts.length ? periodCosts.map((c) => `- ${c.date} ${c.item}: $${c.amountUsd.toFixed(2)}`).join('\n') : '- None this period');
  lines.push(`- Total since start: $${total.toFixed(2)}`);

  lines.push('', '## Traffic and conversions');
  lines.push('- Not connected yet: add Umami (or Cloudflare Web Analytics) and record weekly numbers in METRICS.md.');

  lines.push('', '## System health');
  if (!monitor) lines.push('- Monitor has not run yet.');
  else {
    const s = monitor.summary;
    lines.push(`- Last monitor run: ${s.ranAt} (mail mode: ${monitor.mailMode})`);
    lines.push(`- Domains checked: ${s.domainsChecked}; errored: ${s.domainsErrored}; errors: ${s.errors}`);
    lines.push(`- Emails: welcome ${s.emails.welcome}, alerts ${s.emails.alert}, digests ${s.emails.digest}, failed ${s.emails.failed}, deferred ${s.deferred}`);
  }
  if (providers) {
    const stale = providers.providers.filter((p) => p.stale);
    lines.push(`- Provider pages: ${providers.providers.length} (stale: ${stale.length}${stale.length ? `: ${stale.map((p) => p.id).join(', ')}` : ''}), data from ${providers.generatedAt}`);
  }

  lines.push('', '## Needs a human');
  const human = (monitor?.events || []).filter((e) => e.needsHuman);
  lines.push(human.length ? human.map((e) => `- ${e.msg} (subscription ${e.sub})`).join('\n') : '- Nothing from automated jobs. See ACTION_REQUIRED.md for setup steps.');

  lines.push('', '## Next highest-value improvement');
  let next;
  if (!polarConnected) next = 'Connect payments (ACTION_REQUIRED.md) so the checkout button can take money.';
  else if (!subscribers.length) next = 'No paying customers yet: work on acquisition (submit to directories, check Search Console impressions for provider pages).';
  else if ((monitor?.summary?.errors || 0) > 0) next = 'Fix monitor errors before anything else; paying customers depend on it.';
  else next = 'Improve conversion: compare checker runs to checkout clicks in analytics and test the upsell copy.';
  lines.push(`- ${next}`);
  return lines.join('\n') + '\n';
}
