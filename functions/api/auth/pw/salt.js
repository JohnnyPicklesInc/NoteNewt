/**
 * POST /api/auth/pw/salt  { username }  ->  { pwSalt }
 *
 * Returns the PBKDF2 salt for a username so the client can derive its keys before
 * logging in. To avoid revealing which usernames exist, an unknown username gets
 * a stable, random-looking salt derived from SESSION_SECRET (same length as a
 * real one) — indistinguishable from a real account.
 */
import { json } from '../../../_http.js';
import { b64u } from '../../../_lib.js';

const encoder = new TextEncoder();

function normalize(u) {
  return String(u || '').trim().toLowerCase();
}

async function fakeSalt(secret, username) {
  const key = await crypto.subtle.importKey('raw', encoder.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const mac = new Uint8Array(await crypto.subtle.sign('HMAC', key, encoder.encode('pwsalt:' + username)));
  return b64u(mac.slice(0, 16)); // 16 bytes, matches a real client-generated salt
}

export async function onRequestPost({ request, env }) {
  if (!env.DB || !env.SESSION_SECRET) return json({ error: 'server misconfigured' }, 500);
  let body;
  try {
    body = await request.json();
  } catch {
    return json({ error: 'invalid json' }, 400);
  }
  const username = normalize(body?.username);
  if (!username) return json({ error: 'username required' }, 400);

  const user = await env.DB.prepare('SELECT pw_salt FROM users WHERE username = ?').bind(username).first();
  const pwSalt = user?.pw_salt || (await fakeSalt(env.SESSION_SECRET, username));
  return json({ pwSalt });
}
