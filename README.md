# MailAuth Watch

Free SPF, DKIM and DMARC checker with an SPF DNS-lookup counter, plus optional paid monitoring that emails you when a domain's email authentication changes or breaks.

- **Checker:** runs entirely in the browser over DNS-over-HTTPS (Cloudflare, Google fallback). No backend, nothing stored.
- **Provider pages:** each email provider's SPF include is measured from live DNS daily, with change history.
- **Monitoring:** a daily GitHub Actions job audits subscribed domains and sends welcome, change-alert and weekly emails. Payments via Polar.

## Layout
```
web/          static site (deploy this folder)
  core/       audit engine shared by browser and Node (spf, dmarc, dns, providers, audit)
src/node/     Node-only: resolver, Polar client, mailer (SMTP/Resend), monitor, report, vault
scripts/      provider pages, monitor, report, CLI checker, config builder
tests/        node:test unit tests and a Playwright end-to-end suite
```

## Develop
```
npm test                 # unit tests
npm run test:e2e         # browser tests (needs Playwright + Chromium)
npm run serve            # http://localhost:4173
node scripts/check-domain.mjs example.com
```

## Security notes
- Untrusted DNS data is rendered as text only.
- Monitoring state, logs and reports are encrypted (AES-256-GCM, `STATE_KEY` secret) before being committed to the `ops-state` branch; console logs redact domains.
- Monitoring aborts if a DNS canary check fails, so a broken resolver can't send false "your records vanished" alerts.
- Secrets live only in GitHub Actions secrets; see `.env.example` for names.

## Deploy (free)
Cloudflare Pages: build command `npm run build:config`, output directory `web`.
