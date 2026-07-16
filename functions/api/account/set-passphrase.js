/**
 * POST /api/account/set-passphrase
 *   { username?, pwSaltB64, authSecretB64, wrappedDekB64, wrappedDekIvB64 }
 *   -> { ok }
 *
 * Set OR change the passphrase for the CURRENT (authenticated) account, wrapping
 * the same account DEK under the passphrase key so all unlock methods share one
 * notes key. First time: a `username` is required (and must be free). Changing an
 * existing passphrase (e.g. after recovery): the username is kept.
 */
import { json } from '../../_http.js';
import { sha256OfB64u } from '../../_lib.js';
import { currentUser } from '../../_auth.js';

const USERNAME_RE = /^[a-z0-9_.-]{3,32}$/;

export async function onRequestPost({ request, env }) {
  const me = await currentUser(request, env);
  if (!me) return json({ error: 'not signed in' }, 401);

  let b;
  try {
    b = await request.json();
  } catch {
    return json({ error: 'invalid json' }, 400);
  }
  for (const k of ['pwSaltB64', 'authSecretB64', 'wrappedDekB64', 'wrappedDekIvB64']) {
    if (typeof b?.[k] !== 'string' || !b[k]) return json({ error: `missing ${k}` }, 400);
  }

  const user = await env.DB.prepare('SELECT username FROM users WHERE id = ?').bind(me.userId).first();
  if (!user) return json({ error: 'no such user' }, 404);

  const verifier = await sha256OfB64u(b.authSecretB64);

  if (!user.username) {
    // First time: claim a username.
    const username = String(b?.username || '').trim().toLowerCase();
    if (!USERNAME_RE.test(username)) return json({ error: 'username must be 3–32 chars: letters, numbers, . _ -' }, 400);
    const taken = await env.DB.prepare('SELECT id FROM users WHERE username = ?').bind(username).first();
    if (taken) return json({ error: 'that username is taken' }, 409);
    await env.DB.prepare('UPDATE users SET username=?, pw_salt=?, pw_verifier=?, pw_wrapped_dek=?, pw_wrapped_dek_iv=? WHERE id=?')
      .bind(username, b.pwSaltB64, verifier, b.wrappedDekB64, b.wrappedDekIvB64, me.userId)
      .run();
  } else {
    // Change/reset: keep the existing username.
    await env.DB.prepare('UPDATE users SET pw_salt=?, pw_verifier=?, pw_wrapped_dek=?, pw_wrapped_dek_iv=? WHERE id=?')
      .bind(b.pwSaltB64, verifier, b.wrappedDekB64, b.wrappedDekIvB64, me.userId)
      .run();
  }

  return json({ ok: true });
}
