/**
 * Minimal WebAuthn (passkey) verification for Note Newt, using only Web Crypto —
 * no dependencies, runs in the Worker and under Node for tests. Scope is
 * deliberately narrow: registration with attestation 'none' and ES256 (P-256)
 * assertions, which cover Apple/Android/most platform authenticators.
 *
 * Security checks performed:
 *  - clientDataJSON: correct type, challenge matches an issued+single-use value,
 *    origin matches.
 *  - authenticatorData: rpIdHash === SHA-256(rpId), User-Present flag set.
 *  - assertion: ECDSA signature over authData || SHA-256(clientDataJSON) verifies
 *    against the stored public key; sign counter is non-regressing.
 *
 * Attestation is NOT verified (attestation 'none') — we don't need device
 * provenance for a notes app, only a stable keypair we can authenticate against.
 */
import { b64u, unb64u } from './_lib.js';

const enc = new TextEncoder();
const dec = new TextDecoder();

async function sha256(bytes) {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
}

function bytesEqual(a, b) {
  if (a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a[i] ^ b[i];
  return r === 0;
}

// --- minimal CBOR decoder (maps, arrays, ints, byte/text strings) ------------

/** Decode one CBOR data item. @returns {[value, nextOffset]} */
function cbor(buf, off) {
  const b = buf[off];
  const major = b >> 5;
  const info = b & 0x1f;
  let len = info;
  let o = off + 1;
  if (info === 24) { len = buf[o]; o += 1; }
  else if (info === 25) { len = (buf[o] << 8) | buf[o + 1]; o += 2; }
  else if (info === 26) { len = ((buf[o] << 24) | (buf[o + 1] << 16) | (buf[o + 2] << 8) | buf[o + 3]) >>> 0; o += 4; }
  else if (info === 27) {
    // 64-bit length — read as Number (safe for our small payloads).
    len = 0;
    for (let i = 0; i < 8; i++) len = len * 256 + buf[o + i];
    o += 8;
  } else if (info > 27) {
    throw new Error('cbor: unsupported additional info');
  }

  switch (major) {
    case 0: // unsigned int
      return [len, o];
    case 1: // negative int
      return [-1 - len, o];
    case 2: { // byte string
      const v = buf.subarray(o, o + len);
      return [v, o + len];
    }
    case 3: { // text string
      const v = dec.decode(buf.subarray(o, o + len));
      return [v, o + len];
    }
    case 4: { // array
      const arr = [];
      for (let i = 0; i < len; i++) { const [v, no] = cbor(buf, o); arr.push(v); o = no; }
      return [arr, o];
    }
    case 5: { // map
      const map = new Map();
      for (let i = 0; i < len; i++) {
        const [k, ko] = cbor(buf, o);
        const [v, vo] = cbor(buf, ko);
        map.set(k, v);
        o = vo;
      }
      return [map, o];
    }
    case 6: // tag — skip the tag, decode the tagged item
      return cbor(buf, o);
    case 7: // simple/float — return the raw info (false=20,true=21,null=22)
      return [len, o];
    default:
      throw new Error('cbor: bad major type');
  }
}

// --- authenticator data parsing ----------------------------------------------

/**
 * Parse authenticatorData. When AT (attested-credential) flag is set, also
 * extracts the credential id and COSE public key (registration).
 */
function parseAuthData(ad) {
  if (ad.length < 37) throw new Error('authData too short');
  const rpIdHash = ad.subarray(0, 32);
  const flags = ad[32];
  const signCount = ((ad[33] << 24) | (ad[34] << 16) | (ad[35] << 8) | ad[36]) >>> 0;
  const up = !!(flags & 0x01);
  const uv = !!(flags & 0x04);
  const at = !!(flags & 0x40);

  const out = { rpIdHash, flags, signCount, up, uv, at };
  if (at) {
    // aaguid(16) | credIdLen(2) | credId | COSEKey
    let o = 37 + 16;
    const credIdLen = (ad[o] << 8) | ad[o + 1];
    o += 2;
    out.credentialId = ad.subarray(o, o + credIdLen);
    o += credIdLen;
    const [cose] = cbor(ad, o);
    out.cose = cose;
  }
  return out;
}

/** COSE EC2 key map -> { alg, xB64, yB64 }. Only P-256 / ES256 supported. */
function coseToKey(cose) {
  const kty = cose.get(1);
  const alg = cose.get(3);
  const crv = cose.get(-1);
  const x = cose.get(-2);
  const y = cose.get(-3);
  if (kty !== 2) throw new Error('unsupported key type (need EC2)');
  if (alg !== -7) throw new Error('unsupported alg (need ES256)');
  if (crv !== 1) throw new Error('unsupported curve (need P-256)');
  if (!(x instanceof Uint8Array) || !(y instanceof Uint8Array)) throw new Error('bad COSE coords');
  return { alg, xB64: b64u(x), yB64: b64u(y) };
}

async function importEs256(xB64, yB64) {
  return crypto.subtle.importKey(
    'jwk',
    { kty: 'EC', crv: 'P-256', x: xB64, y: yB64, ext: true },
    { name: 'ECDSA', namedCurve: 'P-256' },
    false,
    ['verify'],
  );
}

/** DER-encoded ECDSA signature -> raw r||s (64 bytes) for Web Crypto verify. */
function derToRaw(der) {
  let o = 0;
  if (der[o++] !== 0x30) throw new Error('bad DER');
  if (der[o] & 0x80) o += 1 + (der[o] & 0x7f); // skip long-form length
  else o += 1;
  const readInt = () => {
    if (der[o++] !== 0x02) throw new Error('bad DER int');
    let len = der[o++];
    let v = der.subarray(o, o + len);
    o += len;
    while (v.length > 0 && v[0] === 0x00) v = v.subarray(1); // strip leading zero
    return v;
  };
  const r = readInt();
  const s = readInt();
  const out = new Uint8Array(64);
  out.set(r, 32 - r.length);
  out.set(s, 64 - s.length);
  return out;
}

function parseClientData(clientDataJSONBytes, { type, challenge, origin }) {
  const data = JSON.parse(dec.decode(clientDataJSONBytes));
  if (data.type !== type) throw new Error('clientData type mismatch');
  if (data.challenge !== challenge) throw new Error('challenge mismatch');
  if (data.origin !== origin) throw new Error('origin mismatch');
  return data;
}

// --- public API --------------------------------------------------------------

/**
 * Verify a registration response (attestation 'none', ES256). Returns the new
 * credential id (base64url) and its public key.
 */
export async function verifyRegistration({ attestationObjectB64, clientDataJSONB64, challenge, origin, rpId }) {
  parseClientData(unb64u(clientDataJSONB64), { type: 'webauthn.create', challenge, origin });
  const [att] = cbor(unb64u(attestationObjectB64), 0);
  const authData = att.get('authData');
  const parsed = parseAuthData(authData);
  if (!parsed.up) throw new Error('user not present');
  if (!bytesEqual(parsed.rpIdHash, await sha256(enc.encode(rpId)))) throw new Error('rpId mismatch');
  if (!parsed.at || !parsed.cose) throw new Error('no attested credential');
  const key = coseToKey(parsed.cose);
  return {
    credentialIdB64: b64u(parsed.credentialId),
    pubkey: { xB64: key.xB64, yB64: key.yB64, alg: key.alg },
    signCount: parsed.signCount,
  };
}

/**
 * Verify an assertion (login) against a stored credential. Throws on any failure;
 * returns the new sign counter on success.
 */
export async function verifyAssertion({
  credential, // { xB64, yB64, alg, signCount }
  authenticatorDataB64,
  clientDataJSONB64,
  signatureB64,
  challenge,
  origin,
  rpId,
}) {
  const clientDataBytes = unb64u(clientDataJSONB64);
  parseClientData(clientDataBytes, { type: 'webauthn.get', challenge, origin });

  const authData = unb64u(authenticatorDataB64);
  const parsed = parseAuthData(authData);
  if (!parsed.up) throw new Error('user not present');
  if (!bytesEqual(parsed.rpIdHash, await sha256(enc.encode(rpId)))) throw new Error('rpId mismatch');

  const signedData = new Uint8Array([...authData, ...(await sha256(clientDataBytes))]);
  const rawSig = derToRaw(unb64u(signatureB64));
  const pub = await importEs256(credential.xB64, credential.yB64);
  const ok = await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, pub, rawSig, signedData);
  if (!ok) throw new Error('signature verification failed');

  // Non-regressing counter (0/0 is allowed for authenticators that don't count).
  if (parsed.signCount !== 0 && parsed.signCount <= (credential.signCount || 0)) {
    throw new Error('sign counter regressed');
  }
  return { signCount: parsed.signCount };
}

/** Compute the RP id (hostname) and expected origin from the request URL. */
export function rpFromRequest(request) {
  const url = new URL(request.url);
  return { rpId: url.hostname, origin: url.origin };
}
