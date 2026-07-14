/**
 * POST /api/auth/passkey/register
 *   { attestationObjectB64, clientDataJSONB64, credentialIdB64, userHandle,
 *     wrappedDekB64, wrappedDekIvB64,
 *     recovery?: { wrappedB64, ivB64, saltB64 }, label? }
 *   -> { ok, userId }   (+ Set-Cookie session)
 *
 * Verifies a passkey registration and stores the credential's public key plus
 * the PRF-wrapped DEK (which the server cannot unwrap → zero-knowledge). If the
 * caller already has a session, the passkey is ADDED to that account (e.g. a new
 * device or post-recovery); otherwise a new account is created from userHandle.
 * Recovery blobs, when present, are stored so a lost-all-passkeys user can get
 * back in via their recovery code.
 */
import { json, sessionCookie } from '../../../_http.js';
import { signSession, SESSION_TTL, unb64u } from '../../../_lib.js';
import { verifyRegistration, rpFromRequest } from '../../../_webauthn.js';
import { currentUser } from '../../../_auth.js';

export async function onRequestPost({ request, env }) {
  if (!env.TOKENS_KV || !env.DB || !env.SESSION_SECRET) return json({ error: 'server misconfigured' }, 500);

  let b;
  try {
    b = await request.json();
  } catch {
    return json({ error: 'invalid json' }, 400);
  }
  for (const k of ['attestationObjectB64', 'clientDataJSONB64', 'credentialIdB64', 'wrappedDekB64', 'wrappedDekIvB64']) {
    if (typeof b?.[k] !== 'string' || !b[k]) return json({ error: `missing ${k}` }, 400);
  }

  // Challenge: single-use, from KV.
  let challenge;
  try {
    challenge = JSON.parse(new TextDecoder().decode(unb64u(b.clientDataJSONB64))).challenge;
  } catch {
    return json({ error: 'bad clientData' }, 400);
  }
  const chalKey = `pkchal:${challenge}`;
  if (!(await env.TOKENS_KV.get(chalKey))) return json({ error: 'challenge expired' }, 400);
  await env.TOKENS_KV.delete(chalKey);

  const { rpId, origin } = rpFromRequest(request);
  let reg;
  try {
    reg = await verifyRegistration({
      attestationObjectB64: b.attestationObjectB64,
      clientDataJSONB64: b.clientDataJSONB64,
      challenge,
      origin,
      rpId,
    });
  } catch (e) {
    return json({ error: `registration failed: ${e.message}` }, 400);
  }

  // Existing session → add this passkey to that account; else create a new user.
  const me = await currentUser(request, env);
  let userId = me?.userId;
  if (!userId) {
    userId = String(b.userHandle || '');
    if (!userId) return json({ error: 'missing userHandle' }, 400);
    await env.DB.prepare('INSERT OR IGNORE INTO users (id, created_at, label) VALUES (?, ?, ?)')
      .bind(userId, Math.floor(Date.now() / 1000), b.label ? String(b.label).slice(0, 80) : null)
      .run();
  }

  await env.DB.prepare(
    `INSERT INTO credentials (credential_id, user_id, pubkey_x, pubkey_y, alg, sign_count, wrapped_dek, wrapped_dek_iv, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
     ON CONFLICT(credential_id) DO NOTHING`,
  )
    .bind(reg.credentialIdB64, userId, reg.pubkey.xB64, reg.pubkey.yB64, reg.pubkey.alg, reg.signCount, b.wrappedDekB64, b.wrappedDekIvB64, Math.floor(Date.now() / 1000))
    .run();

  // Optional recovery blob (set once, at first registration).
  if (b.recovery && b.recovery.wrappedB64 && b.recovery.lookup) {
    await env.DB.prepare(
      'UPDATE users SET recovery_wrapped_dek=?, recovery_iv=?, recovery_salt=?, recovery_lookup=? WHERE id=? AND recovery_lookup IS NULL',
    )
      .bind(b.recovery.wrappedB64, b.recovery.ivB64, b.recovery.saltB64, b.recovery.lookup, userId)
      .run();
  }

  const session = await signSession(env.SESSION_SECRET, userId, Date.now() / 1000);
  return json({ ok: true, userId }, 200, { 'set-cookie': sessionCookie(session, SESSION_TTL) });
}
