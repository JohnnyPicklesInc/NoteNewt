/**
 * Username + passphrase auth for Note Newt — the universal backbone that works on
 * any browser/device (no WebAuthn needed). The passphrase derives two secrets: an
 * encryption key (wraps the DEK, never leaves the device) and an auth secret (the
 * server only stores its SHA-256). Zero-knowledge.
 */
import { deriveFromPassphrase, wrapKey, unwrapKey, wrapForRecovery, b64u, unb64u, randomBytes } from './crypto.js';

async function postJson(path, body) {
  const r = await fetch(path, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
  const data = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(data.error || `request to ${path} failed`);
  return data;
}

/**
 * Create a username + passphrase account, protecting `dek`. Returns
 * { userId, recoveryCode } — show the recovery code once.
 */
export async function registerWithPassphrase(username, passphrase, dek) {
  const salt = randomBytes(16);
  const { encKek, authSecret } = await deriveFromPassphrase(passphrase, salt);
  const w = await wrapKey(encKek, dek);
  const rec = await wrapForRecovery(dek);
  const out = await postJson('/api/auth/pw/register', {
    username,
    pwSaltB64: b64u(salt),
    authSecretB64: b64u(authSecret),
    wrappedDekB64: b64u(w.wrapped),
    wrappedDekIvB64: b64u(w.iv),
    recovery: rec.blob,
  });
  return { userId: out.userId, recoveryCode: rec.code };
}

/** Sign in with username + passphrase. Returns { userId, dek }. */
export async function loginWithPassphrase(username, passphrase) {
  const { pwSalt } = await postJson('/api/auth/pw/salt', { username });
  const { encKek, authSecret } = await deriveFromPassphrase(passphrase, unb64u(pwSalt));
  const out = await postJson('/api/auth/pw/login', { username, authSecretB64: b64u(authSecret) });
  const dek = await unwrapKey(encKek, unb64u(out.dek.ivB64), unb64u(out.dek.wrappedB64));
  return { userId: out.userId, dek };
}

/**
 * Set OR change the passphrase on the current (authenticated) account. Pass a
 * `username` only the first time (omit it when changing an existing passphrase).
 */
export async function setPassphrase(passphrase, dek, username) {
  const salt = randomBytes(16);
  const { encKek, authSecret } = await deriveFromPassphrase(passphrase, salt);
  const w = await wrapKey(encKek, dek);
  const body = {
    pwSaltB64: b64u(salt),
    authSecretB64: b64u(authSecret),
    wrappedDekB64: b64u(w.wrapped),
    wrappedDekIvB64: b64u(w.iv),
  };
  if (username) body.username = username;
  await postJson('/api/account/set-passphrase', body);
}
