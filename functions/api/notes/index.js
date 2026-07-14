/**
 * Notes sync — encrypted blobs only, never plaintext.
 *
 * GET  /api/notes?since=<ms>   -> { notes: [{id, ciphertext, iv, updatedAt, deleted}], now }
 *     Delta pull: this user's notes changed since <ms> (0 = everything), oldest first.
 * POST /api/notes  { notes: [...] } -> { ok, applied }
 *     Bulk push with last-write-wins per note by updatedAt. A note id owned by a
 *     different user is ignored (ids are random UUIDs; this is belt-and-suspenders).
 */
import { json } from '../../_http.js';
import { currentUser } from '../../_auth.js';

export async function onRequestGet({ request, env }) {
  const me = await currentUser(request, env);
  if (!me) return json({ error: 'not signed in' }, 401);

  const since = Number(new URL(request.url).searchParams.get('since')) || 0;
  const rows = await env.DB.prepare(
    'SELECT id, ciphertext, iv, updated_at AS updatedAt, deleted FROM notes WHERE user_id = ? AND updated_at > ? ORDER BY updated_at ASC',
  )
    .bind(me.userId, since)
    .all();

  const notes = (rows.results || []).map((r) => ({
    id: r.id,
    ciphertext: r.ciphertext,
    iv: r.iv,
    updatedAt: r.updatedAt,
    deleted: r.deleted ? 1 : 0,
  }));
  return json({ notes, now: Date.now() });
}

export async function onRequestPost({ request, env }) {
  const me = await currentUser(request, env);
  if (!me) return json({ error: 'not signed in' }, 401);

  let body;
  try {
    body = await request.json();
  } catch {
    return json({ error: 'invalid json' }, 400);
  }
  const incoming = Array.isArray(body?.notes) ? body.notes : [];
  if (incoming.length > 500) return json({ error: 'too many notes in one push' }, 413);
  // Cap per-note ciphertext (~1MB base64 ≈ 750KB plaintext) to bound storage abuse.
  for (const n of incoming) {
    if (n && typeof n.ciphertext === 'string' && n.ciphertext.length > 1_000_000) {
      return json({ error: 'note too large' }, 413);
    }
  }

  const stmt = env.DB.prepare(
    `INSERT INTO notes (id, user_id, ciphertext, iv, updated_at, deleted)
     VALUES (?, ?, ?, ?, ?, ?)
     ON CONFLICT(id) DO UPDATE SET
       ciphertext = excluded.ciphertext,
       iv         = excluded.iv,
       updated_at = excluded.updated_at,
       deleted    = excluded.deleted
     WHERE notes.user_id = excluded.user_id AND excluded.updated_at > notes.updated_at`,
  );

  const batch = [];
  for (const n of incoming) {
    if (!n || typeof n.id !== 'string') continue;
    batch.push(
      stmt.bind(
        n.id,
        me.userId,
        String(n.ciphertext || ''),
        String(n.iv || ''),
        Number(n.updatedAt) || Date.now(),
        n.deleted ? 1 : 0,
      ),
    );
  }
  if (batch.length) await env.DB.batch(batch);

  return json({ ok: true, applied: batch.length });
}
