/**
 * POST /api/list/:id/lock  { ownerSecretB64, locked }  ->  { ok, locked }
 * Owner-only: flip a shared list between editable and read-only. Proves ownership
 * by SHA-256(owner secret) matching the stored owner_hash.
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
  if (!row) return json({ error: 'not found' }, 404);

  const provided = await sha256OfB64u(String(b?.ownerSecretB64 || ''));
  if (!timingSafeEqual(unb64u(provided), unb64u(row.owner_hash))) return json({ error: 'not the owner' }, 403);

  const locked = b?.locked ? 1 : 0;
  await env.DB.prepare('UPDATE shared_lists SET locked=?, updated_at=? WHERE id=?').bind(locked, Date.now(), id).run();
  return json({ ok: true, locked: !!locked });
}
