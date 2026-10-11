// Structured JSON-lines logging. Never pass secrets in; emails are masked by maskEmail().
export function log(level, msg, data = {}) {
  const line = JSON.stringify({ ts: new Date().toISOString(), level, msg, ...data });
  (level === 'error' ? console.error : console.log)(line);
}
export function maskEmail(e) {
  const [u, d] = String(e || '').split('@');
  return d ? `${u.slice(0, 2)}***@${d}` : '***';
}
