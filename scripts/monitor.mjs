#!/usr/bin/env node
// Daily monitoring job. See OPERATIONS.md.
// Env (secrets come from GitHub Actions secrets, never from files in the repo):
//   POLAR_ACCESS_TOKEN, POLAR_SERVER=sandbox|production, POLAR_DOMAIN_FIELD (default "domain")
//   SMTP_USER + SMTP_PASS (free Gmail + app password) or RESEND_API_KEY; MAIL_FROM, SITE_URL, PORTAL_URL
//   SUBSCRIBERS_FILE (JSON array, for local testing instead of Polar), STATE_FILE, LOG_DIR
//   DRY_RUN=1 writes emails to LOG_DIR/outbox instead of sending
//   MAX_DOMAINS, MAX_EMAILS_PER_RUN
import { readFileSync, writeFileSync, mkdirSync, existsSync } from 'node:fs';
import { dirname } from 'node:path';
import { runMonitor } from '../src/node/monitor.js';
import { listActiveSubscribers, polarBase } from '../src/node/polar.js';
import { createMailer } from '../src/node/mailer.js';
import { createNodeResolver } from '../src/node/resolver.js';
import { log } from '../src/node/log.js';

const env = process.env;
const STATE_FILE = env.STATE_FILE || 'state/monitor-state.json';
const LOG_DIR = env.LOG_DIR || 'state/logs';

async function loadSubscribers() {
  if (env.SUBSCRIBERS_FILE) return JSON.parse(readFileSync(env.SUBSCRIBERS_FILE, 'utf8'));
  if (!env.POLAR_ACCESS_TOKEN) { log('warn', 'POLAR_ACCESS_TOKEN not set; no subscribers to check'); return []; }
  return listActiveSubscribers({ token: env.POLAR_ACCESS_TOKEN, baseUrl: polarBase(env), domainField: env.POLAR_DOMAIN_FIELD || 'domain' });
}

async function main() {
  const subscribers = await loadSubscribers();
  const state = existsSync(STATE_FILE) ? JSON.parse(readFileSync(STATE_FILE, 'utf8')) : {};
  const mailer = createMailer({ apiKey: env.RESEND_API_KEY, smtp: { user: env.SMTP_USER, pass: env.SMTP_PASS, host: env.SMTP_HOST || 'smtp.gmail.com', port: Number(env.SMTP_PORT || 465) }, from: env.MAIL_FROM || 'MailAuth Watch <alerts@example.invalid>', outboxDir: `${LOG_DIR}/outbox`, dryRun: env.DRY_RUN === '1' });
  const ctx = { siteUrl: (env.SITE_URL || 'https://example.invalid').replace(/\/$/, ''), portalUrl: env.PORTAL_URL || '(customer portal link in your receipt email)' };
  const limits = {};
  if (env.MAX_DOMAINS) limits.maxDomains = Number(env.MAX_DOMAINS);
  if (env.MAX_EMAILS_PER_RUN) limits.maxEmailsPerRun = Number(env.MAX_EMAILS_PER_RUN);

  const { state: next, summary, events } = await runMonitor({ subscribers, state, resolver: createNodeResolver(), mailer, ctx, limits });
  for (const e of events) log(e.level, e.msg, e);
  mkdirSync(dirname(STATE_FILE), { recursive: true });
  writeFileSync(STATE_FILE, JSON.stringify(next, null, 2) + '\n');
  mkdirSync(LOG_DIR, { recursive: true });
  writeFileSync(`${LOG_DIR}/monitor-latest.json`, JSON.stringify({ summary, mailMode: mailer.mode, events }, null, 2) + '\n');
  log('info', 'monitor run complete', { ...summary, mailMode: mailer.mode });
  if (summary.errors) process.exitCode = 1; // fails the workflow so GitHub emails the owner
}

main().catch((e) => { log('error', 'monitor crashed', { error: String(e?.message || e) }); process.exit(1); });
