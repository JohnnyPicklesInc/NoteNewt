/**
 * GET /api/list/:id  ->  { ciphertextB64, ivB64, version, locked, hasPassphrase, pwSaltB64 }
 * PUT /api/list/:id  { ciphertextB64, ivB64, baseVersion }  ->  { version }
 *
 * GET returns the encrypted list (server can't read it). PUT applies a
 * collaborative edit with optimistic concurrency: the write only lands if
 * baseVersion matches the current version and the list isn't locked — otherwise
 * 409 (stale, re-pull) or 423 (locked). This prevents concurrent edits from
 * silently clobbering each other, even under heavy contention.
 */
import { json } from '../../_http.js';

const MAX_CT = 300000;
const KEEP_VERSIONS = 20;
const ID_RE = /^[A-Za-z0-9_-]{1,32}$/;

export async function onRequestGet({ params, env }) {
  if (!env.DB) return json({ error: 'server misconfigured' }, 500);
  const id = String(params.id || '');
  if (!ID_RE.test(id)) return json({ error: 'not found' }, 404);

  const row = await env.DB.prepare(
    'SELECT ciphertext, iv, version, locked, has_passphrase, pw_salt FROM shared_lists WHERE id = ?',
  )
    .bind(id)
    .first();
  if (!row) return json({ error: 'this list does not exist or was deleted' }, 404);

  return json({
    ciphertextB64: row.ciphertext,
    ivB64: row.iv,
    version: row.version,
    locked: !!row.locked,
    hasPassphrase: !!row.has_passphrase,
    pwSaltB64: row.pw_salt || null,
  });
}

export async function onRequestPut({ params, request, env }) {
  if (!env.DB) return json({ error: 'server misconfigured' }, 500);
  const id = String(params.id || '');
  if (!ID_RE.test(id)) return json({ error: 'not found' }, 404);

  let b;
  try {
    b = await request.json();
  } catch {
    return json({ error: 'invalid json' }, 400);
  }
  const ct = String(b?.ciphertextB64 || '');
  const iv = String(b?.ivB64 || '');
  const baseVersion = Number(b?.baseVersion);
  if (!ct || !iv || !Number.isInteger(baseVersion)) return json({ error: 'missing ciphertext/iv/baseVersion' }, 400);
  if (ct.length > MAX_CT) return json({ error: 'list too large' }, 413);

  const now = Date.now();
  const newVersion = baseVersion + 1;
  const res = await env.DB.prepare(
    'UPDATE shared_lists SET ciphertext=?, iv=?, version=?, updated_at=? WHERE id=? AND version=? AND locked=0',
  )
    .bind(ct, iv, newVersion, now, id, baseVersion)
    .run();

  if (res.meta.changes === 1) {
    // Record the new version and prune old history.
    await env.DB.batch([
      env.DB.prepare('INSERT OR REPLACE INTO shared_list_versions (id, version, ciphertext, iv, updated_at) VALUES (?, ?, ?, ?, ?)').bind(id, newVersion, ct, iv, now),
      env.DB.prepare('DELETE FROM shared_list_versions WHERE id=? AND version <= ?').bind(id, newVersion - KEEP_VERSIONS),
    ]);
    return json({ version: newVersion });
  }

  // Didn't apply — figure out why.
  const cur = await env.DB.prepare('SELECT version, locked FROM shared_lists WHERE id = ?').bind(id).first();
  if (!cur) return json({ error: 'this list does not exist or was deleted' }, 404);
  if (cur.locked) return json({ error: 'this list is locked (read-only)' }, 423);
  return json({ error: 'the list changed — refresh and retry', currentVersion: cur.version }, 409);
}
