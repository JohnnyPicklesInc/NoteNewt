/**
 * Passkey (WebAuthn) auth for Note Newt — native browser API, no library.
 *
 * The passkey's PRF extension yields a stable per-credential secret that never
 * leaves the device; we derive the DEK-wrapping key (KEK) from it, so accounts
 * are zero-knowledge by default. A recovery code wraps a second copy of the DEK
 * as the backup path.
 */
import { b64u, unb64u, wrapKey, unwrapKey, pbkdf2, randomBytes } from './crypto.js';

const PRF_SALT = new TextEncoder().encode('note-newt-prf-v1'); // fixed → stable PRF output
const RC_ALPHABET = 'ABCDEFGHJKMNPQRSTVWXYZ0123456789'; // Crockford base32 (no I,L,O,U)

/** Are passkeys usable in this browser? */
export function passkeysSupported() {
  return typeof window !== 'undefined' && !!window.PublicKeyCredential && !!navigator.credentials;
}

async function sha256(bytes) {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
}
async function sha256b64u(str) {
  return b64u(await sha256(new TextEncoder().encode(str)));
}

/** Normalize a PRF output (ArrayBuffer) to a 32-byte AES key. */
async function kekFromPrf(prfOutput) {
  return sha256(new Uint8Array(prfOutput));
}

function generateRecoveryCode() {
  const bytes = randomBytes(20);
  let s = '';
  for (let i = 0; i < 20; i++) s += RC_ALPHABET[bytes[i] & 31];
  return s.match(/.{1,5}/g).join('-');
}

async function postJson(path, body) {
  const r = await fetch(path, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
  const data = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(data.error || `request to ${path} failed`);
  return data;
}

/** Pull the PRF result from a credential, falling back to a get() if needed. */
async function prfFromCreate(cred, rpId) {
  const ext = cred.getClientExtensionResults();
  if (ext?.prf?.results?.first) return ext.prf.results.first;
  if (!ext?.prf?.enabled) throw new Error('This device/passkey does not support the encryption extension (PRF).');
  // Some authenticators only surface PRF on an assertion — do one now.
  const assertion = await navigator.credentials.get({
    publicKey: {
      challenge: randomBytes(32),
      rpId,
      allowCredentials: [{ type: 'public-key', id: new Uint8Array(cred.rawId) }],
      userVerification: 'preferred',
      extensions: { prf: { eval: { first: PRF_SALT } } },
    },
  });
  const a = assertion.getClientExtensionResults();
  if (!a?.prf?.results?.first) throw new Error('Could not derive an encryption key from this passkey.');
  return a.prf.results.first;
}

/**
 * Create a passkey and register it. Wraps `dek` under the passkey PRF key and a
 * recovery code. Returns { userId, recoveryCode } — show the recovery code once.
 * If `authenticatedAdd` is true this adds a passkey to the current session.
 * @param {Uint8Array} dek The DEK to protect (the device/account data key).
 * @param {{label?: string, authenticatedAdd?: boolean}} [opts]
 */
export async function register(dek, opts = {}) {
  if (!passkeysSupported()) throw new Error('Passkeys are not supported in this browser.');
  const o = await postJson('/api/auth/passkey/register-options', {});

  const cred = await navigator.credentials.create({
    publicKey: {
      challenge: unb64u(o.challenge),
      rp: { name: 'Note Newt', id: o.rpId },
      user: { id: unb64u(o.userHandle), name: opts.label || 'Note Newt', displayName: opts.label || 'Note Newt' },
      pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
      authenticatorSelection: { residentKey: 'required', requireResidentKey: true, userVerification: 'preferred' },
      attestation: 'none',
      extensions: { prf: { eval: { first: PRF_SALT } } },
    },
  });
  if (!cred) throw new Error('Passkey creation was cancelled.');

  const kek = await kekFromPrf(await prfFromCreate(cred, o.rpId));
  const wrapped = await wrapKey(kek, dek);

  // Recovery code: a second wrapped copy of the DEK.
  const recoveryCode = generateRecoveryCode();
  const recSalt = randomBytes(16);
  const recKek = await pbkdf2(recoveryCode, recSalt);
  const recWrapped = await wrapKey(recKek, dek);

  const res = cred.response;
  const body = {
    attestationObjectB64: b64u(res.attestationObject),
    clientDataJSONB64: b64u(res.clientDataJSON),
    credentialIdB64: b64u(cred.rawId),
    userHandle: o.userHandle,
    label: opts.label,
    wrappedDekB64: b64u(wrapped.wrapped),
    wrappedDekIvB64: b64u(wrapped.iv),
    recovery: {
      wrappedB64: b64u(recWrapped.wrapped),
      ivB64: b64u(recWrapped.iv),
      saltB64: b64u(recSalt),
      lookup: await sha256b64u(recoveryCode),
    },
  };
  const out = await postJson('/api/auth/passkey/register', body);
  return { userId: out.userId, recoveryCode };
}

/**
 * Authenticate with an existing passkey. Returns { userId, dek } where dek is the
 * account DEK, unwrapped locally via the passkey PRF key.
 */
export async function authenticate() {
  if (!passkeysSupported()) throw new Error('Passkeys are not supported in this browser.');
  const o = await postJson('/api/auth/passkey/login-options', {});

  const assertion = await navigator.credentials.get({
    publicKey: {
      challenge: unb64u(o.challenge),
      rpId: o.rpId,
      allowCredentials: [], // discoverable — let the user pick their passkey
      userVerification: 'preferred',
      extensions: { prf: { eval: { first: PRF_SALT } } },
    },
  });
  if (!assertion) throw new Error('Sign-in was cancelled.');

  const ext = assertion.getClientExtensionResults();
  if (!ext?.prf?.results?.first) throw new Error('Could not derive your encryption key from this passkey.');
  const kek = await kekFromPrf(ext.prf.results.first);

  const res = assertion.response;
  const out = await postJson('/api/auth/passkey/login', {
    credentialIdB64: b64u(assertion.rawId),
    authenticatorDataB64: b64u(res.authenticatorData),
    clientDataJSONB64: b64u(res.clientDataJSON),
    signatureB64: b64u(res.signature),
  });

  const dek = await unwrapKey(kek, unb64u(out.dek.ivB64), unb64u(out.dek.wrappedB64));
  return { userId: out.userId, dek };
}
