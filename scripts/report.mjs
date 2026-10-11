#!/usr/bin/env node
// Weekly business report. Writes REPORT_DIR/<date>.md and prints it.
import { readFileSync, writeFileSync, mkdirSync, existsSync } from 'node:fs';
import { buildReport } from '../src/node/report.js';
import { listActiveSubscribers, listOrders, polarBase } from '../src/node/polar.js';

const env = process.env;
const readJson = (p) => (existsSync(p) ? JSON.parse(readFileSync(p, 'utf8')) : null);
const today = new Date().toISOString().slice(0, 10);
const periodDays = Number(env.REPORT_DAYS || 7);
const polarConnected = Boolean(env.POLAR_ACCESS_TOKEN);
const opts = { token: env.POLAR_ACCESS_TOKEN, baseUrl: polarBase(env), domainField: env.POLAR_DOMAIN_FIELD || 'domain' };
const since = new Date(Date.now() - periodDays * 86400000).toISOString();

const [orders, subscribers] = polarConnected ? await Promise.all([listOrders(opts, since), listActiveSubscribers(opts)]) : [[], []];
const md = buildReport({
  today, periodDays, orders, subscribers, polarConnected, polarMode: env.POLAR_SERVER || 'sandbox',
  costs: readJson(env.COSTS_FILE || 'data/costs.json') || [],
  monitor: readJson(`${env.LOG_DIR || 'state/logs'}/monitor-latest.json`),
  providers: readJson(env.DATA_FILE || 'data/providers.json'),
});
const dir = env.REPORT_DIR || 'state/reports';
mkdirSync(dir, { recursive: true });
writeFileSync(`${dir}/${today}.md`, md);
console.log(md);
