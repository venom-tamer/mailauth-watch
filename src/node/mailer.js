// Sends transactional email. Transports, in order of preference:
//   smtp   - free Gmail account + app password (SMTP_USER/SMTP_PASS), $0, 500/day
//   resend - Resend API (RESEND_API_KEY), needs a verified domain you own
//   outbox - writes JSON files instead of sending (no credentials, or DRY_RUN=1)
import { mkdirSync, writeFileSync } from 'node:fs';
import { sendSmtp } from './smtp.js';

export function createMailer({ apiKey, smtp, from, outboxDir, dryRun, fetchImpl = fetch, smtpSend = sendSmtp }) {
  let seq = 0;
  // Gmail shows app passwords in groups of four; spaces pasted with them are not part of it.
  if (smtp?.pass) smtp = { ...smtp, user: String(smtp.user || '').trim(), pass: String(smtp.pass).replace(/\s+/g, '') };
  const mode = dryRun ? 'outbox' : smtp?.user && smtp?.pass ? 'smtp' : apiKey ? 'resend' : 'outbox';
  return {
    mode,
    async send({ to, subject, text, html, idempotencyKey }) {
      if (mode === 'smtp') return smtpSend({ ...smtp, from, to, subject, text });
      if (mode === 'outbox') {
        mkdirSync(outboxDir, { recursive: true });
        const file = `${outboxDir}/${Date.now()}-${++seq}.json`;
        writeFileSync(file, JSON.stringify({ to, from, subject, text, idempotencyKey }, null, 2));
        return { ok: true, id: file };
      }
      const res = await fetchImpl('https://api.resend.com/emails', {
        method: 'POST',
        headers: { authorization: `Bearer ${apiKey}`, 'content-type': 'application/json', ...(idempotencyKey ? { 'idempotency-key': idempotencyKey } : {}) },
        body: JSON.stringify({ from, to: [to], subject, text, html }),
      });
      if (!res.ok) return { ok: false, error: `Resend HTTP ${res.status}` };
      const j = await res.json().catch(() => ({}));
      return { ok: true, id: j.id };
    },
  };
}
