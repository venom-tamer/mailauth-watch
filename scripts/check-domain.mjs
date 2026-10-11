#!/usr/bin/env node
// Usage: node scripts/check-domain.mjs example.com [--json]
import { auditDomain, suggestSpf } from '../web/core/audit.js';
import { normalizeDomain, isValidDomain, createDohResolver } from '../web/core/dns.js';
import { createNodeResolver } from '../src/node/resolver.js';

const domain = normalizeDomain(process.argv[2]);
if (!isValidDomain(domain)) { console.error('Usage: check-domain.mjs <domain> [--json] [--doh]'); process.exit(2); }
const resolver = process.argv.includes('--doh') ? createDohResolver() : createNodeResolver();
const rep = await auditDomain(domain, resolver);
if (process.argv.includes('--json')) { delete rep.spf.tree; console.log(JSON.stringify(rep, null, 2)); process.exit(0); }
console.log(`${rep.domain}: grade ${rep.grade} (${rep.score}/100), SPF lookups ${rep.spf.lookups}/10`);
for (const i of rep.issues) console.log(`- [${i.severity}] ${i.area}: ${i.message}${i.fix ? `\n    fix: ${i.fix}` : ''}`);
const s = suggestSpf(rep); if (s && s !== rep.spf.record) console.log(`Suggested SPF: ${s}`);
