/**
 * GET /api/list-refs  ->  { ciphertextB64, ivB64, updatedAt } | { empty: true }
 * PUT /api/list-refs  { ciphertextB64, ivB64, updatedAt }  ->  { ok }
 *
 * A per-account encrypted bundle of the user's shared-list references, so their
 * shared lists follow them across devices. Encrypted client-side with the account
 * DEK — the server holds only ciphertext. PUT is last-write-wins by updatedAt.
 */
import { json } from '../_http.js';
import { currentUser } from '../_auth.js';

export async function onRequestGet({ request, env }) {
  const me = await currentUser(request, env);
  if (!me) return json({ error: 'not signed in' }, 401);
  const row = await env.DB.prepare('SELECT ciphertext, iv, updated_at FROM user_lists WHERE user_id = ?').bind(me.userId).first();
  if (!row) return json({ empty: true });
  return json({ ciphertextB64: row.ciphertext, ivB64: row.iv, updatedAt: row.updated_at });
}

export async function onRequestPut({ request, env }) {
  const me = await currentUser(request, env);
  if (!me) return json({ error: 'not signed in' }, 401);
  let b;
  try {
    b = await request.json();
  } catch {
    return json({ error: 'invalid json' }, 400);
  }
  const ct = String(b?.ciphertextB64 || '');
  const iv = String(b?.ivB64 || '');
  if (!ct || !iv) return json({ error: 'missing ciphertext/iv' }, 400);
  if (ct.length > 400000) return json({ error: 'too large' }, 413);
  const updatedAt = Number(b?.updatedAt) || Date.now();

  await env.DB.prepare(
    `INSERT INTO user_lists (user_id, ciphertext, iv, updated_at) VALUES (?, ?, ?, ?)
     ON CONFLICT(user_id) DO UPDATE SET ciphertext=excluded.ciphertext, iv=excluded.iv, updated_at=excluded.updated_at
     WHERE excluded.updated_at >= user_lists.updated_at`,
  )
    .bind(me.userId, ct, iv, updatedAt)
    .run();
  return json({ ok: true });
}
