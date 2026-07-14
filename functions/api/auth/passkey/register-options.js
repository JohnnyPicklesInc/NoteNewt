/**
 * POST /api/auth/passkey/register-options -> { challenge, rpId, userHandle }
 *
 * Issues a single-use registration challenge (stored in KV, 5-min TTL) and a
 * fresh random WebAuthn user handle that becomes the account id.
 */
import { json } from '../../../_http.js';
import { randomToken } from '../../../_lib.js';
import { rpFromRequest } from '../../../_webauthn.js';

const CHALLENGE_TTL = 300;

export async function onRequestPost({ request, env }) {
  if (!env.TOKENS_KV) return json({ error: 'server misconfigured' }, 500);
  const challenge = randomToken(32);
  const userHandle = randomToken(16);
  await env.TOKENS_KV.put(`pkchal:${challenge}`, '1', { expirationTtl: CHALLENGE_TTL });
  const { rpId } = rpFromRequest(request);
  return json({ challenge, rpId, userHandle });
}
