/**
 * POST /api/account/recover  { recoveryCode }  ->  { userId, recovery }  (+ session)
 *
 * The recovery code is a bearer secret: hashing it locates the account and proves
 * ownership, so we issue a session and return the recovery-wrapped DEK blob. The
 * client derives the DEK from the code locally, then registers a new passkey.
 * (The raw code is never stored — only its SHA-256 as `recovery_lookup`.)
 */
import { json, sessionCookie } from '../../_http.js';
import { signSession, sha256b64u, SESSION_TTL } from '../../_lib.js';

export async function onRequestPost({ request, env }) {
  if (!env.DB || !env.SESSION_SECRET) return json({ error: 'server misconfigured' }, 500);

  let b;
  try {
    b = await request.json();
  } catch {
    return json({ error: 'invalid json' }, 400);
  }
  const code = String(b?.recoveryCode || '').trim().toUpperCase();
  if (!code) return json({ error: 'enter your recovery code' }, 400);

  const lookup = await sha256b64u(code);
  const user = await env.DB.prepare(
    'SELECT id, recovery_wrapped_dek, recovery_iv, recovery_salt FROM users WHERE recovery_lookup = ?',
  )
    .bind(lookup)
    .first();
  if (!user || !user.recovery_wrapped_dek) return json({ error: 'invalid recovery code' }, 400);

  const session = await signSession(env.SESSION_SECRET, user.id, Date.now() / 1000);
  return json(
    {
      userId: user.id,
      recovery: { wrappedB64: user.recovery_wrapped_dek, ivB64: user.recovery_iv, saltB64: user.recovery_salt },
    },
    200,
    { 'set-cookie': sessionCookie(session, SESSION_TTL) },
  );
}
