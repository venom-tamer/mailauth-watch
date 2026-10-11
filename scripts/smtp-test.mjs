#!/usr/bin/env node
// Sends one test email from the configured Gmail account to itself, to prove SMTP works.
// Prints only ok/failed (never addresses or the password).
import { createMailer } from '../src/node/mailer.js';

const env = process.env;
const note = (kind, text) => console.log(env.GITHUB_ACTIONS ? `::${kind} title=SMTP test::${text}` : text);
if (!env.SMTP_USER || !env.SMTP_PASS) { note('error', 'SMTP_USER or SMTP_PASS secret not set'); process.exit(1); }
const mailer = createMailer({ smtp: { user: env.SMTP_USER.trim(), pass: env.SMTP_PASS.replace(/\s+/g, '') }, from: env.MAIL_FROM || `MailAuth Watch <${env.SMTP_USER.trim()}>` });
try {
  const r = await mailer.send({ to: env.SMTP_USER.trim(), subject: 'MailAuth Watch: email sending works', text: 'This is a test from the MailAuth Watch smtp-test job. Customer alerts will be sent from this account.\n' });
  if (r?.ok === false) throw new Error(r.error);
  note('notice', 'Gmail accepted the test email (check the inbox of the sending account)');
} catch (e) {
  note('error', `send failed: ${String(e?.message || e).slice(0, 200)}`);
  process.exit(1);
}
