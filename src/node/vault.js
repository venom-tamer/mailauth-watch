// Encrypts operational files (monitoring state, logs, reports) with AES-256-GCM so they can
// live in a public repository. Key: the STATE_KEY secret (any long random string).
import { createCipheriv, createDecipheriv, randomBytes, scryptSync, createHash } from 'node:crypto';
import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'node:fs';
import { dirname } from 'node:path';

const MAGIC = 'MAWENC1';

export function encrypt(plaintext, passphrase) {
  if (!passphrase || passphrase.length < 16) throw new Error('STATE_KEY must be at least 16 characters');
  const salt = randomBytes(16);
  const iv = randomBytes(12);
  const key = scryptSync(passphrase, salt, 32);
  const c = createCipheriv('aes-256-gcm', key, iv);
  const body = Buffer.concat([c.update(Buffer.from(plaintext, 'utf8')), c.final()]);
  return [MAGIC, salt.toString('base64'), iv.toString('base64'), c.getAuthTag().toString('base64'), body.toString('base64')].join('.');
}

export function decrypt(blob, passphrase) {
  const [magic, salt, iv, tag, body] = String(blob).trim().split('.');
  if (magic !== MAGIC) throw new Error('not an encrypted MailAuth Watch file');
  const key = scryptSync(passphrase, Buffer.from(salt, 'base64'), 32);
  const d = createDecipheriv('aes-256-gcm', key, Buffer.from(iv, 'base64'));
  d.setAuthTag(Buffer.from(tag, 'base64'));
  return Buffer.concat([d.update(Buffer.from(body, 'base64')), d.final()]).toString('utf8');
}

/** Reads `path` (plain JSON) or `path.enc` (encrypted JSON). Returns null if neither exists. */
export function readJson(path, key) {
  if (key && existsSync(`${path}.enc`)) return JSON.parse(decrypt(readFileSync(`${path}.enc`, 'utf8'), key));
  if (existsSync(path)) return JSON.parse(readFileSync(path, 'utf8'));
  return null;
}

/** Writes encrypted `path.enc` when a key is given, else plain `path`. */
export function writeText(path, text, key) {
  mkdirSync(dirname(path), { recursive: true });
  if (key) writeFileSync(`${path}.enc`, encrypt(text, key) + '\n');
  else writeFileSync(path, text);
}

/** Stable, non-reversible label for a domain in public logs. */
export function redactDomain(d) {
  return `domain#${createHash('sha256').update(String(d)).digest('hex').slice(0, 8)}`;
}
