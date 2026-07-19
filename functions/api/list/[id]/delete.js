/**
 * POST /api/list/:id/delete  { ownerSecretB64 }  ->  { ok }
 * Owner-only: permanently delete a shared list and its version history.
 */
import { json } from '../../../_http.js';
import { sha256OfB64u, timingSafeEqual, unb64u } from '../../../_lib.js';

export async function onRequestPost({ params, request, env }) {
  if (!env.DB) return json({ error: 'server misconfigured' }, 500);
  const id = String(params.id || '');

  let b;
  try {
    b = await request.json();
  } catch {
    return json({ error: 'invalid json' }, 400);
  }
  const row = await env.DB.prepare('SELECT owner_hash FROM shared_lists WHERE id = ?').bind(id).first();
  if (!row) return json({ ok: true }); // already gone

  const provided = await sha256OfB64u(String(b?.ownerSecretB64 || ''));
  if (!timingSafeEqual(unb64u(provided), unb64u(row.owner_hash))) return json({ error: 'not the owner' }, 403);

  await env.DB.batch([
    env.DB.prepare('DELETE FROM shared_lists WHERE id=?').bind(id),
    env.DB.prepare('DELETE FROM shared_list_versions WHERE id=?').bind(id),
  ]);
  return json({ ok: true });
}
