/**
 * Session middleware helper. Resolves the current user from the signed session
 * cookie, or null when unauthenticated. Endpoints that require auth call this
 * first and 401 on null.
 */
import { verifySession } from './_lib.js';
import { parseCookies } from './_http.js';

/**
 * @param {Request} request
 * @param {object} env Worker env (reads SESSION_SECRET).
 * @returns {Promise<{userId: string} | null>}
 */
export async function currentUser(request, env) {
  if (!env.SESSION_SECRET) return null;
  const cookies = parseCookies(request.headers.get('cookie'));
  const token = cookies.nn_session;
  if (!token) return null;
  const session = await verifySession(env.SESSION_SECRET, token, Date.now() / 1000);
  return session ? { userId: session.userId } : null;
}
