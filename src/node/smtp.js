// Minimal SMTP client (implicit TLS, AUTH PLAIN) for sending through a free Gmail account
// with an app password: smtp.gmail.com:465. No dependencies. Limit: 500 messages/day.
import tls from 'node:tls';
import { randomUUID } from 'node:crypto';

function encodeHeader(s) {
  return /^[\x20-\x7e]*$/.test(s) ? s : `=?UTF-8?B?${Buffer.from(s).toString('base64')}?=`;
}

export function buildMessage({ from, to, subject, text, date = new Date(), messageIdDomain = 'mailauth.local' }) {
  const body = Buffer.from(text.replace(/\r?\n/g, '\r\n')).toString('base64').replace(/.{76}/g, '$&\r\n');
  return [
    `From: ${from}`,
    `To: ${to}`,
    `Subject: ${encodeHeader(subject)}`,
    `Date: ${date.toUTCString()}`,
    `Message-ID: <${randomUUID()}@${messageIdDomain}>`,
    'MIME-Version: 1.0',
    'Content-Type: text/plain; charset=UTF-8',
    'Content-Transfer-Encoding: base64',
    '',
    body,
  ].join('\r\n');
}

const addrOf = (s) => (s.match(/<([^>]+)>/) || [null, s])[1].trim();

/** connect: () => Duplex socket already in TLS (overridable for tests). */
export async function sendSmtp({ host = 'smtp.gmail.com', port = 465, user, pass, from, to, subject, text, connect, timeoutMs = 20000 }) {
  if (/[\r\n]/.test(to + from + subject)) throw new Error('header injection rejected');
  const sock = connect ? connect() : tls.connect({ host, port, servername: host });
  sock.setEncoding?.('utf8');
  let buf = '';
  const waiters = [];
  sock.on('data', (d) => {
    buf += d;
    // A complete reply ends with a line "NNN text" (space, not dash, after the code)
    const m = buf.match(/(?:^|\r\n)(\d{3}) [^\r\n]*\r\n$/);
    if (m && waiters.length) { const w = waiters.shift(); const all = buf; buf = ''; w(all); }
  });
  const timer = setTimeout(() => sock.destroy(new Error('SMTP timeout')), timeoutMs);
  const errored = new Promise((_, rej) => sock.on('error', rej));
  const read = () => Promise.race([new Promise((r) => waiters.push(r)), errored]);
  const expect = async (code, cmd) => {
    if (cmd != null) sock.write(cmd + '\r\n');
    const reply = await read();
    const last = reply.trim().split('\r\n').pop();
    if (!last.startsWith(String(code))) throw new Error(`SMTP ${cmd ? cmd.split(' ')[0] : 'greeting'} failed: ${last.slice(0, 120)}`);
    return reply;
  };
  try {
    await expect(220);
    await expect(250, 'EHLO mailauth-watch');
    await expect(235, `AUTH PLAIN ${Buffer.from(`\0${user}\0${pass}`).toString('base64')}`);
    await expect(250, `MAIL FROM:<${addrOf(from)}>`);
    await expect(250, `RCPT TO:<${addrOf(to)}>`);
    await expect(354, 'DATA');
    const msg = buildMessage({ from, to, subject, text }).replace(/\r\n\./g, '\r\n..');
    await expect(250, `${msg}\r\n.`);
    sock.write('QUIT\r\n');
    return { ok: true };
  } catch (e) {
    return { ok: false, error: e.message.replace(/AUTH PLAIN \S+/, 'AUTH PLAIN ***') };
  } finally {
    clearTimeout(timer);
    sock.end?.();
  }
}
