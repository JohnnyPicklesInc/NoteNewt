/**
 * Server-side helpers for Note Newt. Runs in the Cloudflare Worker (Pages
 * Functions) and is also imported by scripts/selftest.mjs under Node, so it uses
 * only standard Web Crypto + TextEncoder + btoa/atob available in both.
 *
 * Responsibilities:
 *   - base64url + HMAC + constant-time compare (kept in sync with public/crypto.js;
 *     scripts/selftest.mjs asserts parity).
 *   - Stateless signed session cookies (no session table).
 *   - SHA-256 hashing for WebAuthn challenges and recovery-code lookups.
 *
 * Passkey accounts are zero-knowledge: the DEK is wrapped client-side under the
 * passkey's PRF secret, so there is no server-held key material here.
 */

const encoder = new TextEncoder();

export const SESSION_TTL = 60 * 60 * 24 * 30; // 30 days, seconds

/**
 * Encode bytes as unpadded base64url. Kept in sync with public/crypto.js.
 * @param {Uint8Array | ArrayBuffer} bytes
 * @returns {string}
 */
export function b64u(bytes) {
  const b = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let s = '';
  for (let i = 0; i < b.length; i++) s += String.fromCharCode(b[i]);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/**
 * Decode a base64url string (padded or not) to bytes.
 * @param {string} str
 * @returns {Uint8Array}
 */
export function unb64u(str) {
  const s = String(str).replace(/-/g, '+').replace(/_/g, '/');
  const pad = s + '='.repeat((4 - (s.length % 4)) % 4);
  const bin = atob(pad);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

async function hmac(keyBytes, msg) {
  const key = await crypto.subtle.importKey('raw', keyBytes, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const data = typeof msg === 'string' ? encoder.encode(msg) : msg;
  return new Uint8Array(await crypto.subtle.sign('HMAC', key, data));
}

/**
 * Constant-time byte-array comparison. The early length-mismatch return leaks
 * only length, which isn't secret here.
 * @param {Uint8Array} a
 * @param {Uint8Array} b
 * @returns {boolean}
 */
export function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a[i] ^ b[i];
  return r === 0;
}

/** SHA-256 of a UTF-8 string, as base64url. */
export async function sha256b64u(str) {
  const digest = await crypto.subtle.digest('SHA-256', encoder.encode(str));
  return b64u(digest);
}

/** SHA-256 of the RAW bytes decoded from a base64url string, as base64url.
 *  Used to turn a client-sent authSecret into the stored passphrase verifier. */
export async function sha256OfB64u(b64uStr) {
  return b64u(await crypto.subtle.digest('SHA-256', unb64u(b64uStr)));
}

/** HMAC-SHA-256(secret, msg) as base64url. */
export async function hmacSha256b64u(secretStr, msg) {
  return b64u(await hmac(encoder.encode(secretStr), msg));
}

/** Random URL-safe token (default 32 bytes ≈ 43 chars). @returns {string} */
export function randomToken(n = 32) {
  return b64u(crypto.getRandomValues(new Uint8Array(n)));
}

// --- Sessions ----------------------------------------------------------------

/**
 * Mint a stateless signed session token: `userId.exp.HMAC(secret, "userId.exp")`.
 * @param {string} secret SESSION_SECRET.
 * @param {string} userId
 * @param {number} nowSec Unix seconds.
 * @param {number} [ttl=SESSION_TTL]
 * @returns {Promise<string>}
 */
export async function signSession(secret, userId, nowSec, ttl = SESSION_TTL) {
  const exp = Math.floor(nowSec) + ttl;
  const payload = `${userId}.${exp}`;
  const sig = await hmac(encoder.encode(secret), payload);
  return `${payload}.${b64u(sig)}`;
}

/**
 * Verify a session token and return its userId if authentic and unexpired.
 * @param {string} secret SESSION_SECRET.
 * @param {string} token The cookie value.
 * @param {number} nowSec Unix seconds.
 * @returns {Promise<{userId: string, exp: number} | null>}
 */
export async function verifySession(secret, token, nowSec) {
  const parts = String(token || '').split('.');
  if (parts.length !== 3) return null;
  const [userId, expStr, sigB64] = parts;
  const exp = Number(expStr);
  if (!userId || !Number.isInteger(exp)) return null;
  const expected = await hmac(encoder.encode(secret), `${userId}.${exp}`);
  let provided;
  try {
    provided = unb64u(sigB64);
  } catch {
    return null;
  }
  if (!timingSafeEqual(expected, provided)) return null;
  if (Math.floor(nowSec) >= exp) return null;
  return { userId, exp };
}
