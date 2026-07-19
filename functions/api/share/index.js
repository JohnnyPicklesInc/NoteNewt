/**
 * POST /api/share  { ciphertextB64, ivB64 }  ->  { id, expiresInDays }
 *
 * Stores an end-to-end-encrypted note blob for sharing. The decryption key never
 * reaches the server — it travels in the link's #fragment. We only hold opaque
 * ciphertext, keyed by a random id, in KV with a 30-day TTL (self-expiring).
 * Sharing is open (works for anonymous users too); abuse is bounded by a size
 * cap plus the edge rate limit.
 */
import { json } from '../../_http.js';
import { randomToken } from '../../_lib.js';

const SHARE_TTL_DAYS = 30;

export async function onRequestPost({ request, env }) {
  if (!env.TOKENS_KV) return json({ error: 'server misconfigured' }, 500);

  let b;
  try {
    b = await request.json();
  } catch {
    return json({ error: 'invalid json' }, 400);
  }
  const ct = String(b?.ciphertextB64 || '');
  const iv = String(b?.ivB64 || '');
  if (!ct || !iv) return json({ error: 'missing ciphertext/iv' }, 400);
  if (ct.length > 300000) return json({ error: 'note too large to share' }, 413);

  const id = randomToken(12);
  await env.TOKENS_KV.put(`share:${id}`, JSON.stringify({ ct, iv }), {
    expirationTtl: 60 * 60 * 24 * SHARE_TTL_DAYS,
  });
  return json({ id, expiresInDays: SHARE_TTL_DAYS });
}
