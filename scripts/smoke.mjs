/**
 * HTTP smoke test against a running dev server (`npm run dev`). Passkey auth
 * needs a real WebAuthn authenticator, so the full account lifecycle lives in
 * the browser E2E (`npm run e2e`). This checks the plumbing that doesn't need an
 * authenticator: challenge issuance, auth gating, and that static pages serve.
 *
 * Run:  npm run dev   (one terminal)
 *       npm run smoke  (another)
 */
const BASE = process.env.BASE_URL || 'http://localhost:8788';
let pass = 0, fail = 0;
const check = (n, c) => { c ? (pass++, console.log(`  ok   ${n}`)) : (fail++, console.log(`  FAIL ${n}`)); };

async function json(path, opts) {
  const r = await fetch(BASE + path, opts);
  let data = null;
  try { data = await r.json(); } catch { /* non-json */ }
  return { status: r.status, data };
}

// Challenge issuance
const reg = await json('/api/auth/passkey/register-options', { method: 'POST' });
check('register-options returns challenge + rpId + userHandle',
  reg.status === 200 && reg.data.challenge && reg.data.rpId && reg.data.userHandle);
const login = await json('/api/auth/passkey/login-options', { method: 'POST' });
check('login-options returns challenge + rpId', login.status === 200 && login.data.challenge && login.data.rpId);
check('two challenges differ', reg.data.challenge !== login.data.challenge);

// Auth gating
check('notes pull requires auth (401)', (await json('/api/notes?since=0')).status === 401);
check('account/me requires auth (401)', (await json('/api/account/me')).status === 401);
check('register rejects an empty body (400)',
  (await json('/api/auth/passkey/register', { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}' })).status === 400);
check('login rejects a forged assertion (400)',
  (await json('/api/auth/passkey/login', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ credentialIdB64: 'x', authenticatorDataB64: 'x', clientDataJSONB64: 'x', signatureB64: 'x' }) })).status === 400);

// Recovery + ads + static
check('recover rejects a bad code (400)',
  (await json('/api/account/recover', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ recoveryCode: 'NOPE-NOPE-NOPE-NOPE' }) })).status === 400);
check('house ad serves', (await json('/api/ad')).status === 200);

for (const p of ['/', '/app', '/login', '/recover', '/no-signup-notes', '/private-notes-online', '/encrypted-notepad', '/privacy', '/robots.txt', '/sitemap.xml']) {
  const r = await fetch(BASE + p);
  check(`GET ${p} -> 200`, r.ok);
}

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
