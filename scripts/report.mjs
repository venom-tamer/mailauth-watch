#!/usr/bin/env node
// Weekly business report. Writes REPORT_DIR/<date>.md and prints it.
import { readFileSync, existsSync } from 'node:fs';
import { readJson, writeText } from '../src/node/vault.js';
import { createMailer } from '../src/node/mailer.js';
import { buildReport } from '../src/node/report.js';
import { listActiveSubscribers, listOrders, polarBase } from '../src/node/polar.js';

const env = process.env;
const readPlain = (p) => (existsSync(p) ? JSON.parse(readFileSync(p, 'utf8')) : null);
const today = new Date().toISOString().slice(0, 10);
const periodDays = Number(env.REPORT_DAYS || 7);
const polarConnected = Boolean(env.POLAR_ACCESS_TOKEN);
const opts = { token: env.POLAR_ACCESS_TOKEN, baseUrl: polarBase(env), domainField: env.POLAR_DOMAIN_FIELD || 'domain' };
const since = new Date(Date.now() - periodDays * 86400000).toISOString();

const [orders, subscribers] = polarConnected ? await Promise.all([listOrders(opts, since), listActiveSubscribers(opts)]) : [[], []];
const md = buildReport({
  today, periodDays, orders, subscribers, polarConnected, polarMode: env.POLAR_SERVER || 'sandbox',
  costs: readPlain(env.COSTS_FILE || 'data/costs.json') || [],
  monitor: readJson(`${env.LOG_DIR || 'state/logs'}/monitor-latest.json`, env.STATE_KEY),
  providers: readPlain(env.DATA_FILE || 'data/providers.json'),
});
const dir = env.REPORT_DIR || 'state/reports';
writeText(`${dir}/${today}.md`, md, env.STATE_KEY);
// The report holds revenue and customer counts: send it privately, never print it to public logs.
if (env.OWNER_EMAIL && env.SMTP_USER && env.SMTP_PASS) {
  const mailer = createMailer({ smtp: { user: env.SMTP_USER, pass: env.SMTP_PASS }, from: env.MAIL_FROM || env.SMTP_USER });
  const r = await mailer.send({ to: env.OWNER_EMAIL, subject: `MailAuth Watch weekly report ${today}`, text: md });
  console.log(r.ok ? 'report emailed to owner' : `report email failed: ${r.error}`);
  if (!r.ok) process.exitCode = 1;
} else if (env.STATE_KEY) {
  console.log(`report written encrypted to ${dir}/${today}.md.enc (set OWNER_EMAIL to receive it by email)`);
} else {
  console.log(md);
}
