/**
 * POST /api/auth/pw/login  { username, authSecretB64 }
 *   -> { ok, userId, dek: { wrappedB64, ivB64, saltB64 } }   (+ session cookie)
 *
 * Verifies the passphrase-derived authSecret against the stored verifier and
 * returns the passphrase-wrapped DEK. The client derives the encryption key from
 * the passphrase locally and unwraps it — the server never sees the key.
 * Errors are generic to avoid revealing whether a username exists.
 */
import { json, sessionCookie } from '../../../_http.js';
import { signSession, sha256OfB64u, timingSafeEqual, unb64u, SESSION_TTL } from '../../../_lib.js';

export async function onRequestPost({ request, env }) {
  if (!env.DB || !env.SESSION_SECRET) return json({ error: 'server misconfigured' }, 500);

  let b;
  try {
    b = await request.json();
  } catch {
    return json({ error: 'invalid json' }, 400);
  }
  const username = String(b?.username || '').trim().toLowerCase();
  if (!username || typeof b?.authSecretB64 !== 'string') return json({ error: 'invalid username or passphrase' }, 400);

  const user = await env.DB.prepare(
    'SELECT id, pw_verifier, pw_wrapped_dek, pw_wrapped_dek_iv, pw_salt FROM users WHERE username = ?',
  )
    .bind(username)
    .first();

  const generic = () => json({ error: 'invalid username or passphrase' }, 400);
  if (!user || !user.pw_verifier) return generic();

  const provided = await sha256OfB64u(b.authSecretB64);
  let ok;
  try {
    ok = timingSafeEqual(unb64u(provided), unb64u(user.pw_verifier));
  } catch {
    return generic();
  }
  if (!ok) return generic();

  const session = await signSession(env.SESSION_SECRET, user.id, Date.now() / 1000);
  return json(
    { ok: true, userId: user.id, dek: { wrappedB64: user.pw_wrapped_dek, ivB64: user.pw_wrapped_dek_iv, saltB64: user.pw_salt } },
    200,
    { 'set-cookie': sessionCookie(session, SESSION_TTL) },
  );
}
