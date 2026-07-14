/**
 * POST /api/account/delete  ->  { ok: true }   (clears the session cookie)
 *
 * Permanently deletes the signed-in account: all notes, all passkey credentials,
 * and the user row. The client also wipes its local data. Irreversible.
 */
import { json, clearSessionCookie } from '../../_http.js';
import { currentUser } from '../../_auth.js';

export async function onRequestPost({ request, env }) {
  const me = await currentUser(request, env);
  if (!me) return json({ error: 'not signed in' }, 401);

  // Delete children before the parent. D1 batch runs sequentially in one call.
  await env.DB.batch([
    env.DB.prepare('DELETE FROM notes WHERE user_id = ?').bind(me.userId),
    env.DB.prepare('DELETE FROM credentials WHERE user_id = ?').bind(me.userId),
    env.DB.prepare('DELETE FROM users WHERE id = ?').bind(me.userId),
  ]);

  return json({ ok: true }, 200, { 'set-cookie': clearSessionCookie() });
}
