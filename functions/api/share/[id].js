/**
 * GET /api/share/:id  ->  { ciphertextB64, ivB64 }  or 404
 *
 * Returns the stored ciphertext for a shared note. The server cannot read it —
 * the key is only in the recipient's link fragment.
 */
import { json } from '../../_http.js';

const ID_RE = /^[A-Za-z0-9_-]{1,32}$/;

export async function onRequestGet({ params, env }) {
  if (!env.TOKENS_KV) return json({ error: 'server misconfigured' }, 500);
  const id = String(params.id || '');
  if (!ID_RE.test(id)) return json({ error: 'not found' }, 404);

  const rec = await env.TOKENS_KV.get(`share:${id}`, 'json');
  if (!rec || !rec.ct || !rec.iv) {
    return json({ error: 'this shared note has expired or does not exist' }, 404);
  }
  return json({ ciphertextB64: rec.ct, ivB64: rec.iv });
}
