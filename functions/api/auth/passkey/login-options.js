/**
 * POST /api/auth/passkey/login-options -> { challenge, rpId }
 *
 * Issues a single-use assertion challenge (KV, 5-min TTL). allowCredentials is
 * left empty on the client so any discoverable passkey for this site can be used.
 */
import { json } from '../../../_http.js';
import { randomToken } from '../../../_lib.js';
import { rpFromRequest } from '../../../_webauthn.js';

const CHALLENGE_TTL = 300;

export async function onRequestPost({ request, env }) {
  if (!env.TOKENS_KV) return json({ error: 'server misconfigured' }, 500);
  const challenge = randomToken(32);
  await env.TOKENS_KV.put(`pkchal:${challenge}`, '1', { expirationTtl: CHALLENGE_TTL });
  const { rpId } = rpFromRequest(request);
  return json({ challenge, rpId });
}
