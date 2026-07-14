/**
 * Client-side crypto for Note Newt. Pure Web Crypto — runs in the browser, and
 * (being standards-only) is also imported by scripts/selftest.mjs under Node.
 *
 * The base primitives (b64u, pbkdf2, AES-GCM helpers) are lifted from WhisperFox
 * so the two projects stay in lock-step; scripts/selftest.mjs asserts parity with
 * functions/_lib.js.
 *
 * Note Newt uses envelope encryption:
 *   - Each note is encrypted with a single per-user 256-bit DEK (data key).
 *   - The DEK itself is stored *wrapped* (AES-GCM-encrypted) under a KEK, which is
 *     either a server-held master key (default) or PBKDF2(passphrase) (zero-knowledge).
 * Only the DEK ever touches note plaintext; upgrading to a passphrase re-wraps the
 * DEK without re-encrypting a single note.
 */

const encoder = new TextEncoder();
const decoder = new TextDecoder();

/**
 * Encode bytes as unpadded base64url.
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
 * @throws {Error} If the input is not valid base64.
 */
export function unb64u(str) {
  const s = String(str).replace(/-/g, '+').replace(/_/g, '/');
  const pad = s + '='.repeat((4 - (s.length % 4)) % 4);
  const bin = atob(pad);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

/**
 * Cryptographically secure random bytes.
 * @param {number} n Byte count.
 * @returns {Uint8Array}
 */
export function randomBytes(n) {
  return crypto.getRandomValues(new Uint8Array(n));
}

/**
 * Derive a 256-bit key from a secret phrase (PBKDF2, SHA-256, 600k iterations).
 * @param {string} phrase
 * @param {Uint8Array} salt
 * @returns {Promise<Uint8Array>} 32-byte derived key.
 */
export async function pbkdf2(phrase, salt) {
  const material = await crypto.subtle.importKey('raw', encoder.encode(phrase), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations: 600000, hash: 'SHA-256' },
    material,
    256,
  );
  return new Uint8Array(bits);
}

/**
 * Encrypt raw bytes with AES-256-GCM under a fresh random IV.
 * @param {Uint8Array} keyBytes 32-byte key.
 * @param {Uint8Array} plainBytes
 * @returns {Promise<{iv: Uint8Array, ct: Uint8Array}>} 12-byte IV and ciphertext (tag included).
 */
export async function aesEncryptBytes(keyBytes, plainBytes) {
  const key = await crypto.subtle.importKey('raw', keyBytes, 'AES-GCM', false, ['encrypt']);
  const iv = randomBytes(12);
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, plainBytes));
  return { iv, ct };
}

/**
 * Decrypt AES-256-GCM ciphertext back to raw bytes.
 * @param {Uint8Array} keyBytes 32-byte key.
 * @param {Uint8Array} iv 12-byte IV from aesEncryptBytes.
 * @param {Uint8Array} ct Ciphertext (tag included).
 * @returns {Promise<Uint8Array>}
 * @throws {Error} If the key is wrong or the ciphertext was tampered with.
 */
export async function aesDecryptBytes(keyBytes, iv, ct) {
  const key = await crypto.subtle.importKey('raw', keyBytes, 'AES-GCM', false, ['decrypt']);
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct);
  return new Uint8Array(pt);
}

/**
 * Encrypt UTF-8 text with AES-256-GCM.
 * @param {Uint8Array} keyBytes 32-byte key.
 * @param {string} plaintext
 * @returns {Promise<{iv: Uint8Array, ct: Uint8Array}>}
 */
export async function aesEncrypt(keyBytes, plaintext) {
  return aesEncryptBytes(keyBytes, encoder.encode(plaintext));
}

/**
 * Decrypt AES-256-GCM ciphertext back to UTF-8 text.
 * @param {Uint8Array} keyBytes 32-byte key.
 * @param {Uint8Array} iv 12-byte IV.
 * @param {Uint8Array} ct Ciphertext (tag included).
 * @returns {Promise<string>}
 */
export async function aesDecrypt(keyBytes, iv, ct) {
  return decoder.decode(await aesDecryptBytes(keyBytes, iv, ct));
}

// --- Envelope helpers --------------------------------------------------------

/** Mint a fresh random 256-bit data-encryption key (DEK). @returns {Uint8Array} */
export function generateDek() {
  return randomBytes(32);
}

/**
 * Wrap (encrypt) a raw key under a KEK. The KEK is a server master key or a
 * PBKDF2(passphrase) output; the wrapped blob is safe to hand to the server.
 * @param {Uint8Array} kekBytes 32-byte key-encryption key.
 * @param {Uint8Array} keyBytes The raw DEK bytes to wrap.
 * @returns {Promise<{iv: Uint8Array, wrapped: Uint8Array}>}
 */
export async function wrapKey(kekBytes, keyBytes) {
  const { iv, ct } = await aesEncryptBytes(kekBytes, keyBytes);
  return { iv, wrapped: ct };
}

/**
 * Unwrap (decrypt) a DEK previously produced by wrapKey.
 * @param {Uint8Array} kekBytes 32-byte key-encryption key.
 * @param {Uint8Array} iv 12-byte IV from wrapKey.
 * @param {Uint8Array} wrapped The wrapped DEK bytes.
 * @returns {Promise<Uint8Array>} The raw DEK bytes.
 * @throws {Error} If the KEK is wrong (e.g. wrong passphrase) or the blob was tampered with.
 */
export async function unwrapKey(kekBytes, iv, wrapped) {
  return aesDecryptBytes(kekBytes, iv, wrapped);
}

/**
 * Whether subtle Web Crypto is usable. Requires a secure context (HTTPS or
 * localhost); false over plain http://<ip>.
 * @returns {boolean}
 */
export function webCryptoAvailable() {
  return !!(globalThis.isSecureContext && globalThis.crypto?.subtle);
}
