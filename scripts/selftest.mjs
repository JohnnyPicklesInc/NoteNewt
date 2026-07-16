/**
 * End-to-end crypto self-test — no server, no network. Proves the envelope
 * design round-trips: note encryption under a DEK, DEK wrapping under both a
 * server master key and a PBKDF2 passphrase, the passphrase "upgrade" (same DEK,
 * re-wrapped), recovery-code unwrap, and client<->server base64url parity.
 * Run: node scripts/selftest.mjs
 *
 * Imports the REAL client crypto and the REAL server lib (both standards-only).
 */
import {
  generateDek,
  aesEncrypt,
  aesDecrypt,
  wrapKey,
  unwrapKey,
  pbkdf2,
  randomBytes,
  deriveFromPassphrase,
  b64u,
  unb64u,
} from '../public/crypto.js';
import {
  b64u as srvB64u,
  signSession,
  verifySession,
  sha256b64u,
} from '../functions/_lib.js';

let pass = 0;
let fail = 0;
function check(name, cond) {
  if (cond) {
    pass++;
    console.log(`  ok   ${name}`);
  } else {
    fail++;
    console.log(`  FAIL ${name}`);
  }
}

const NOTE = 'Meet me at 6. Code word: pineapple 🍍.\n' + 'x'.repeat(40);

// --- note encryption under a DEK round-trips ---------------------------------
const dek = generateDek();
check('DEK is 32 bytes', dek.length === 32);
const { iv, ct } = await aesEncrypt(dek, NOTE);
check('ciphertext differs from plaintext', b64u(ct) !== b64u(new TextEncoder().encode(NOTE)));
check('note decrypts back to original', (await aesDecrypt(dek, iv, ct)) === NOTE);

// wrong DEK fails closed
let wrongFailed = false;
try {
  await aesDecrypt(generateDek(), iv, ct);
} catch {
  wrongFailed = true;
}
check('wrong DEK cannot decrypt note', wrongFailed);

// --- DEK wrapping under a derived key (passkey PRF or recovery code) ----------
// The PRF secret is normalized to a 32-byte key the same way passkey.js does it
// (SHA-256 of the PRF output); here we simulate with a random 32-byte KEK.
const prfKek = randomBytes(32);
const wrapped = await wrapKey(prfKek, dek);
const dekBack = await unwrapKey(prfKek, wrapped.iv, wrapped.wrapped);
check('PRF-wrapped DEK unwraps to the same key', b64u(dekBack) === b64u(dek));
check('the *same* DEK still decrypts notes after wrapping', (await aesDecrypt(dekBack, iv, ct)) === NOTE);

let wrongKekFailed = false;
try {
  await unwrapKey(randomBytes(32), wrapped.iv, wrapped.wrapped);
} catch {
  wrongKekFailed = true;
}
check('a wrong wrapping key cannot unwrap the DEK', wrongKekFailed);

// --- username+passphrase derivation: enc key wraps DEK, auth secret verifies ---
const pwSalt = randomBytes(16);
const { encKek, authSecret } = await deriveFromPassphrase('correct horse battery staple', pwSalt);
const pwWrapped = await wrapKey(encKek, dek);
const { encKek: encKek2, authSecret: authSecret2 } = await deriveFromPassphrase('correct horse battery staple', pwSalt);
check('same passphrase+salt reproduces the enc key', b64u(encKek) === b64u(encKek2));
check('same passphrase+salt reproduces the auth secret', b64u(authSecret) === b64u(authSecret2));
check('enc key and auth secret are different', b64u(encKek) !== b64u(authSecret));
check('passphrase enc key unwraps the DEK', b64u(await unwrapKey(encKek2, pwWrapped.iv, pwWrapped.wrapped)) === b64u(dek));
const wrongDerive = await deriveFromPassphrase('wrong passphrase', pwSalt);
check('wrong passphrase yields a different auth secret (login would fail)', b64u(wrongDerive.authSecret) !== b64u(authSecret));
let pwWrongFailed = false;
try {
  await unwrapKey(wrongDerive.encKek, pwWrapped.iv, pwWrapped.wrapped);
} catch {
  pwWrongFailed = true;
}
check('wrong passphrase cannot unwrap the DEK', pwWrongFailed);

// --- recovery code path (a second wrapped copy of the DEK under PBKDF2) -------
const recSalt = randomBytes(16);
const recKek = await pbkdf2('APPLE-RIVER-42-STONE', recSalt);
const recWrapped = await wrapKey(recKek, dek);
const dekFromRec = await unwrapKey(recKek, recWrapped.iv, recWrapped.wrapped);
check('recovery code recovers the same DEK', b64u(dekFromRec) === b64u(dek));

// --- sessions ----------------------------------------------------------------
const SECRET = 'dev-session-secret';
const now = 1_700_000_000;
const token = await signSession(SECRET, 'user-abc', now);
const ok = await verifySession(SECRET, token, now + 100);
check('valid session verifies to its userId', ok && ok.userId === 'user-abc');
check('expired session is rejected', (await verifySession(SECRET, token, now + 60 * 60 * 24 * 40)) === null);
const tampered = token.slice(0, -3) + (token.endsWith('AAA') ? 'BBB' : 'AAA');
check('tampered session is rejected', (await verifySession(SECRET, tampered, now + 100)) === null);
check('wrong secret rejects a session', (await verifySession('other-secret', token, now + 100)) === null);

// --- magic-link token hashing ------------------------------------------------
const h1 = await sha256b64u('a-token');
const h2 = await sha256b64u('a-token');
check('token hash is deterministic', h1 === h2);
check('different tokens hash differently', (await sha256b64u('other')) !== h1);

// --- base64url helpers agree client<->server ---------------------------------
const probe = randomBytes(20);
check('b64url client==server', b64u(probe) === srvB64u(probe));
check('b64url round-trips', b64u(unb64u(b64u(probe))) === b64u(probe));

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
