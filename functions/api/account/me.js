/**
 * GET /api/account/me  ->  { userId, label, passkeys, hasRecovery }  (401 if not signed in)
 */
import { json } from '../../_http.js';
import { currentUser } from '../../_auth.js';

export async function onRequestGet({ request, env }) {
  const me = await currentUser(request, env);
  if (!me) return json({ error: 'not signed in' }, 401);
  const user = await env.DB.prepare('SELECT label, username, recovery_lookup FROM users WHERE id = ?').bind(me.userId).first();
  if (!user) return json({ error: 'no such user' }, 404);
  const count = await env.DB.prepare('SELECT COUNT(*) AS n FROM credentials WHERE user_id = ?').bind(me.userId).first();
  return json({
    userId: me.userId,
    label: user.label,
    username: user.username || null,
    passkeys: count?.n || 0,
    hasRecovery: !!user.recovery_lookup,
  });
}
