// Known mail providers and sending services.
// `spf` is the include a customer adds; `match` detects the service in an existing SPF
// record or MX host; `selectors` are DKIM selectors the service commonly uses.
// Lookup costs are NOT hard-coded: they are measured live from DNS (scripts/build-provider-pages.mjs),
// because providers change their records and static tables go stale.

export const PROVIDERS = [
  { id: 'google-workspace', name: 'Google Workspace', kind: 'mailbox', spf: '_spf.google.com', match: [/_spf\.google\.com/, /(^|\.)google\.com$/, /googlemail\.com$/], selectors: ['google'] },
  { id: 'microsoft-365', name: 'Microsoft 365 / Exchange Online', kind: 'mailbox', spf: 'spf.protection.outlook.com', match: [/spf\.protection\.outlook\.com/, /mail\.protection\.outlook\.com$/], selectors: ['selector1', 'selector2'] },
  { id: 'zoho-mail', name: 'Zoho Mail', kind: 'mailbox', spf: 'zohomail.com', match: [/(^|\.)zoho(mail)?\.(com|eu|in|com\.au)$/, /include:zoho/], selectors: ['zmail', 'zoho'] },
  { id: 'proton-mail', name: 'Proton Mail', kind: 'mailbox', spf: '_spf.protonmail.ch', match: [/protonmail\.ch/], selectors: ['protonmail', 'protonmail2', 'protonmail3'] },
  { id: 'fastmail', name: 'Fastmail', kind: 'mailbox', spf: 'spf.messagingengine.com', match: [/messagingengine\.com/], selectors: ['fm1', 'fm2', 'fm3'] },
  { id: 'godaddy', name: 'GoDaddy email', kind: 'mailbox', spf: 'secureserver.net', match: [/secureserver\.net/], selectors: [] },
  { id: 'namecheap-private-email', name: 'Namecheap Private Email', kind: 'mailbox', spf: 'spf.privateemail.com', match: [/privateemail\.com/], selectors: ['default'] },
  { id: 'hostinger', name: 'Hostinger email', kind: 'mailbox', spf: '_spf.mail.hostinger.com', match: [/hostinger\.com/], selectors: ['hostingermail1', 'hostingermail2', 'hostingermail3'] },
  { id: 'sendgrid', name: 'SendGrid', kind: 'sender', spf: 'sendgrid.net', match: [/sendgrid\.net/], selectors: ['s1', 's2', 'smtpapi'] },
  { id: 'mailgun', name: 'Mailgun', kind: 'sender', spf: 'mailgun.org', match: [/mailgun\.org/], selectors: ['mx', 'smtp', 'k1', 'krs'] },
  { id: 'amazon-ses', name: 'Amazon SES', kind: 'sender', spf: 'amazonses.com', match: [/amazonses\.com/], selectors: [] },
  { id: 'mailchimp', name: 'Mailchimp', kind: 'sender', spf: 'servers.mcsv.net', match: [/mcsv\.net/], selectors: ['k1', 'k2', 'k3'] },
  { id: 'mandrill', name: 'Mailchimp Transactional (Mandrill)', kind: 'sender', spf: 'spf.mandrillapp.com', match: [/mandrillapp\.com/], selectors: ['mandrill', 'mte1', 'mte2'] },
  { id: 'brevo', name: 'Brevo (Sendinblue)', kind: 'sender', spf: 'spf.brevo.com', match: [/brevo\.com/, /sendinblue\.com/], selectors: ['mail', 'brevo1', 'brevo2'] },
  { id: 'mailjet', name: 'Mailjet', kind: 'sender', spf: 'spf.mailjet.com', match: [/mailjet\.com/], selectors: ['mailjet'] },
  { id: 'postmark', name: 'Postmark', kind: 'sender', spf: 'spf.mtasv.net', match: [/mtasv\.net/], selectors: [] },
  { id: 'sparkpost', name: 'SparkPost', kind: 'sender', spf: 'sparkpostmail.com', match: [/sparkpostmail\.com/], selectors: ['scph0124'] },
  { id: 'salesforce', name: 'Salesforce', kind: 'sender', spf: '_spf.salesforce.com', match: [/salesforce\.com/], selectors: [] },
  { id: 'hubspot', name: 'HubSpot', kind: 'sender', spf: null, match: [/hubspotemail\.net/], selectors: ['hs1', 'hs2'] },
  { id: 'zendesk', name: 'Zendesk', kind: 'sender', spf: 'mail.zendesk.com', match: [/zendesk\.com/], selectors: ['zendesk1', 'zendesk2'] },
  { id: 'freshdesk', name: 'Freshdesk', kind: 'sender', spf: 'email.freshdesk.com', match: [/freshdesk\.com/], selectors: ['fd', 'fd2'] },
  { id: 'shopify', name: 'Shopify', kind: 'sender', spf: 'shops.shopify.com', match: [/shopify\.com/], selectors: [] },
];

export const GENERIC_SELECTORS = ['default', 'dkim', 'mail', 'selector', 's1', 's2', 'k1', 'key1', 'email', 'smtp'];

export function detectProviders(spfRecord, mxHosts) {
  const hay = [String(spfRecord || '').toLowerCase(), ...(mxHosts || []).map((h) => h.toLowerCase())];
  return PROVIDERS.filter((p) => p.match.some((re) => hay.some((h) => re.test(h))));
}
