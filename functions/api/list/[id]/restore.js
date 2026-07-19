/**
 * POST /api/list/:id/restore  { ownerSecretB64, toVersion }  ->  { version }
 * Owner-only: restore the list's content to an earlier kept version (one-click
 * revert of vandalism). Applies it as a new version so history stays linear.
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
  const list = await env.DB.prepare('SELECT owner_hash, version FROM shared_lists WHERE id = ?').bind(id).first();
  if (!list) return json({ error: 'not found' }, 404);

  const provided = await sha256OfB64u(String(b?.ownerSecretB64 || ''));
  if (!timingSafeEqual(unb64u(provided), unb64u(list.owner_hash))) return json({ error: 'not the owner' }, 403);

  const toVersion = Number(b?.toVersion);
  if (!Number.isInteger(toVersion)) return json({ error: 'invalid version' }, 400);
  const old = await env.DB.prepare('SELECT ciphertext, iv FROM shared_list_versions WHERE id=? AND version=?').bind(id, toVersion).first();
  if (!old) return json({ error: 'that version is no longer available' }, 404);

  const now = Date.now();
  const newVersion = list.version + 1;
  await env.DB.batch([
    env.DB.prepare('UPDATE shared_lists SET ciphertext=?, iv=?, version=?, updated_at=? WHERE id=?').bind(old.ciphertext, old.iv, newVersion, now, id),
    env.DB.prepare('INSERT OR REPLACE INTO shared_list_versions (id, version, ciphertext, iv, updated_at) VALUES (?, ?, ?, ?, ?)').bind(id, newVersion, old.ciphertext, old.iv, now),
  ]);
  return json({ version: newVersion });
}
