/**
 * POST /api/auth/passkey/login
 *   { credentialIdB64, authenticatorDataB64, clientDataJSONB64, signatureB64 }
 *   -> { ok, userId, dek: { wrappedB64, ivB64 } }   (+ Set-Cookie session)
 *
 * Verifies a passkey assertion against the stored public key and returns that
 * credential's PRF-wrapped DEK. The client unwraps it locally with the passkey's
 * PRF secret — the server never sees the key.
 */
import { json, sessionCookie } from '../../../_http.js';
import { signSession, SESSION_TTL, unb64u } from '../../../_lib.js';
import { verifyAssertion, rpFromRequest } from '../../../_webauthn.js';

export async function onRequestPost({ request, env }) {
  if (!env.TOKENS_KV || !env.DB || !env.SESSION_SECRET) return json({ error: 'server misconfigured' }, 500);

  let b;
  try {
    b = await request.json();
  } catch {
    return json({ error: 'invalid json' }, 400);
  }
  for (const k of ['credentialIdB64', 'authenticatorDataB64', 'clientDataJSONB64', 'signatureB64']) {
    if (typeof b?.[k] !== 'string' || !b[k]) return json({ error: `missing ${k}` }, 400);
  }

  let challenge;
  try {
    challenge = JSON.parse(new TextDecoder().decode(unb64u(b.clientDataJSONB64))).challenge;
  } catch {
    return json({ error: 'bad clientData' }, 400);
  }
  const chalKey = `pkchal:${challenge}`;
  if (!(await env.TOKENS_KV.get(chalKey))) return json({ error: 'challenge expired' }, 400);
  await env.TOKENS_KV.delete(chalKey);

  const cred = await env.DB.prepare('SELECT * FROM credentials WHERE credential_id = ?').bind(b.credentialIdB64).first();
  if (!cred) return json({ error: 'unknown passkey' }, 400);

  const { rpId, origin } = rpFromRequest(request);
  let result;
  try {
    result = await verifyAssertion({
      credential: { xB64: cred.pubkey_x, yB64: cred.pubkey_y, alg: cred.alg, signCount: cred.sign_count },
      authenticatorDataB64: b.authenticatorDataB64,
      clientDataJSONB64: b.clientDataJSONB64,
      signatureB64: b.signatureB64,
      challenge,
      origin,
      rpId,
    });
  } catch (e) {
    return json({ error: `login failed: ${e.message}` }, 400);
  }

  await env.DB.prepare('UPDATE credentials SET sign_count = ? WHERE credential_id = ?')
    .bind(result.signCount, b.credentialIdB64)
    .run();

  const session = await signSession(env.SESSION_SECRET, cred.user_id, Date.now() / 1000);
  return json(
    {
      ok: true,
      userId: cred.user_id,
      dek: {
        wrappedB64: cred.wrapped_dek,
        ivB64: cred.wrapped_dek_iv,
        keyType: cred.key_type || 'prf',
        dekSaltB64: cred.dek_salt || null,
      },
    },
    200,
    { 'set-cookie': sessionCookie(session, SESSION_TTL) },
  );
}
