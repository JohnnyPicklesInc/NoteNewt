/**
 * POST /api/auth/logout  ->  { ok: true }   (clears the session cookie)
 * Local notes are wiped client-side; the server just drops the session.
 */
import { json, clearSessionCookie } from '../../_http.js';

export async function onRequestPost() {
  return json({ ok: true }, 200, { 'set-cookie': clearSessionCookie() });
}
