/**
 * Passkey (WebAuthn) auth for Note Newt — native browser API, no library.
 *
 * The passkey's PRF extension yields a stable per-credential secret that never
 * leaves the device; we derive the DEK-wrapping key (KEK) from it, so accounts
 * are zero-knowledge by default. A recovery code wraps a second copy of the DEK
 * as the backup path.
 */
import { b64u, unb64u, wrapKey, unwrapKey, pbkdf2, randomBytes, wrapForRecovery } from './crypto.js';

const PRF_SALT = new TextEncoder().encode('note-newt-prf-v1'); // fixed → stable PRF output

/** Are passkeys usable in this browser? */
export function passkeysSupported() {
  return typeof window !== 'undefined' && !!window.PublicKeyCredential && !!navigator.credentials;
}

/** Normalize a PRF output (ArrayBuffer) to a 32-byte AES key. */
async function kekFromPrf(prfOutput) {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', new Uint8Array(prfOutput)));
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
 * Create a passkey and register it. The DEK is wrapped either under the passkey
 * PRF key (zero-knowledge, no passphrase) or — when the browser lacks PRF, e.g.
 * Firefox — under a passphrase the caller supplies via `opts.getPassphrase`.
 * Also wraps a recovery-code copy. Returns { userId, recoveryCode, keyType }.
 * @param {Uint8Array} dek The DEK to protect (the device/account data key).
 * @param {{label?: string, authenticatedAdd?: boolean, getPassphrase?: () => Promise<string>}} [opts]
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

  // Choose the key source: PRF if the authenticator supports it, else passphrase.
  const ext = cred.getClientExtensionResults();
  let keyType, saltB64, wrapped;
  if (ext?.prf?.enabled) {
    const kek = await kekFromPrf(await prfFromCreate(cred, o.rpId));
    wrapped = await wrapKey(kek, dek);
    keyType = 'prf';
  } else {
    if (!opts.getPassphrase) throw new Error('PRF_UNAVAILABLE');
    const passphrase = await opts.getPassphrase();
    const salt = randomBytes(16);
    const kek = await pbkdf2(passphrase, salt);
    wrapped = await wrapKey(kek, dek);
    saltB64 = b64u(salt);
    keyType = 'passphrase';
  }

  // Recovery code: a second wrapped copy of the DEK (always PBKDF2).
  const rec = await wrapForRecovery(dek);

  const res = cred.response;
  const body = {
    attestationObjectB64: b64u(res.attestationObject),
    clientDataJSONB64: b64u(res.clientDataJSON),
    credentialIdB64: b64u(cred.rawId),
    userHandle: o.userHandle,
    label: opts.label,
    keyType,
    dekSaltB64: saltB64,
    wrappedDekB64: b64u(wrapped.wrapped),
    wrappedDekIvB64: b64u(wrapped.iv),
    recovery: rec.blob,
  };
  const out = await postJson('/api/auth/passkey/register', body);
  return { userId: out.userId, recoveryCode: rec.code, keyType };
}

/**
 * Authenticate with an existing passkey. Returns { userId, dek }. The DEK is
 * unwrapped either via the passkey PRF key or a passphrase (from
 * `opts.getPassphrase`), depending on how the credential was registered.
 * @param {{getPassphrase?: () => Promise<string>}} [opts]
 */
export async function authenticate(opts = {}) {
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

  const res = assertion.response;
  const out = await postJson('/api/auth/passkey/login', {
    credentialIdB64: b64u(assertion.rawId),
    authenticatorDataB64: b64u(res.authenticatorData),
    clientDataJSONB64: b64u(res.clientDataJSON),
    signatureB64: b64u(res.signature),
  });

  let kek;
  if (out.dek.keyType === 'passphrase') {
    if (!opts.getPassphrase) throw new Error('PASSPHRASE_REQUIRED');
    kek = await pbkdf2(await opts.getPassphrase(), unb64u(out.dek.dekSaltB64));
  } else {
    const ext = assertion.getClientExtensionResults();
    if (!ext?.prf?.results?.first) throw new Error('Could not derive your encryption key from this passkey.');
    kek = await kekFromPrf(ext.prf.results.first);
  }

  const dek = await unwrapKey(kek, unb64u(out.dek.ivB64), unb64u(out.dek.wrappedB64));
  return { userId: out.userId, dek };
}
