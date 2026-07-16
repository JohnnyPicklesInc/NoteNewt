/**
 * POST /api/auth/pw/register
 *   { username, pwSaltB64, authSecretB64, wrappedDekB64, wrappedDekIvB64,
 *     recovery?: { wrappedB64, ivB64, saltB64, lookup } }
 *   -> { ok, userId }   (+ session cookie)
 *
 * Creates a username + passphrase account. The server stores only the salt, a
 * verifier (SHA-256 of the client's authSecret), and the passphrase-wrapped DEK
 * — never the passphrase or the encryption key. Zero-knowledge.
 */
import { json, sessionCookie } from '../../../_http.js';
import { signSession, sha256OfB64u, SESSION_TTL } from '../../../_lib.js';

const USERNAME_RE = /^[a-z0-9_.-]{3,32}$/;

export async function onRequestPost({ request, env }) {
  if (!env.DB || !env.SESSION_SECRET) return json({ error: 'server misconfigured' }, 500);

  let b;
  try {
    b = await request.json();
  } catch {
    return json({ error: 'invalid json' }, 400);
  }
  const username = String(b?.username || '').trim().toLowerCase();
  if (!USERNAME_RE.test(username)) {
    return json({ error: 'username must be 3–32 chars: letters, numbers, . _ -' }, 400);
  }
  for (const k of ['pwSaltB64', 'authSecretB64', 'wrappedDekB64', 'wrappedDekIvB64']) {
    if (typeof b?.[k] !== 'string' || !b[k]) return json({ error: `missing ${k}` }, 400);
  }

  const existing = await env.DB.prepare('SELECT id FROM users WHERE username = ?').bind(username).first();
  if (existing) return json({ error: 'that username is taken' }, 409);

  const userId = crypto.randomUUID();
  const verifier = await sha256OfB64u(b.authSecretB64);
  const rec = b.recovery && b.recovery.wrappedB64 && b.recovery.lookup ? b.recovery : null;

  try {
    await env.DB.prepare(
      `INSERT INTO users (id, created_at, username, pw_salt, pw_verifier, pw_wrapped_dek, pw_wrapped_dek_iv,
                          recovery_wrapped_dek, recovery_iv, recovery_salt, recovery_lookup)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    )
      .bind(
        userId, Math.floor(Date.now() / 1000), username, b.pwSaltB64, verifier, b.wrappedDekB64, b.wrappedDekIvB64,
        rec ? rec.wrappedB64 : null, rec ? rec.ivB64 : null, rec ? rec.saltB64 : null, rec ? rec.lookup : null,
      )
      .run();
  } catch (e) {
    if (String(e).includes('UNIQUE')) return json({ error: 'that username is taken' }, 409);
    throw e;
  }

  const session = await signSession(env.SESSION_SECRET, userId, Date.now() / 1000);
  return json({ ok: true, userId }, 200, { 'set-cookie': sessionCookie(session, SESSION_TTL) });
}
