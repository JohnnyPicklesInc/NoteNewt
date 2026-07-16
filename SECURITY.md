# Security model

Note Newt encrypts every note client-side. Accounts are passkey-based and
zero-knowledge. Nothing here substitutes for reading the code — start at
`public/crypto.js`, `public/passkey.js`, `public/sync.js`, and
`functions/_webauthn.js`.

## Keys

- **DEK (data-encryption key)** — a random 256-bit AES-GCM key; the only key that ever
  encrypts note plaintext. Minted on a device the first time you use the app (anonymous),
  and adopted as the account key when you create a passkey.
- **KEK (key-encryption key)** — wraps the DEK for storage:
  - **Passphrase (primary):** `master = PBKDF2(passphrase, salt, 600000)`, split via HMAC into
    an **encryption key** (`HMAC(master,"enc")`, wraps the DEK, never sent) and an **auth secret**
    (`HMAC(master,"auth")`, sent at login; the server stores only its SHA-256 as a verifier).
    The passphrase and encryption key never reach the server; the auth secret can't decrypt
    anything. Works on any browser — this is the account backbone.
  - **Passkey PRF (optional):** `KEK = SHA-256(PRF output)`. The passkey's WebAuthn PRF secret is
    produced on the authenticator and never leaves the device. A synced passkey
    (iCloud Keychain / Google Password Manager) yields the same PRF output on the user's
    other devices, so they can unwrap the DEK; the server cannot. A fast-unlock accelerator on
    top of the passphrase account.
  - **Passphrase (no-PRF fallback):** on browsers without the PRF extension (e.g. Firefox),
    `KEK = PBKDF2(passphrase, salt, 600000, SHA-256)`. The passkey still authenticates; only
    the key source changes. The credential row records `key_type = 'passphrase'` and the salt;
    still zero-knowledge (the passphrase never leaves the device).
  - **Recovery code:** `KEK = PBKDF2(recovery code, salt, 600000, SHA-256)`, wrapping a
    second copy of the DEK. Shown once at registration; only its SHA-256 is stored, as a
    lookup handle.

The server stores the passkey **public** key and the wrapped DEKs, never a PRF secret,
passphrase, or raw key.

## Passkey verification (`functions/_webauthn.js`)

- Registration (attestation `none`): validates the client data type, that the challenge was
  server-issued and single-use, and the origin; checks `rpIdHash === SHA-256(rpId)` and the
  User-Present flag; extracts and stores the ES256 (P-256) public key. Attestation is not
  verified — we don't need device provenance, only a keypair to authenticate against.
- Assertion (login): re-checks challenge/origin/rpIdHash/UP, then verifies the ECDSA-P-256
  signature over `authenticatorData || SHA-256(clientDataJSON)` with the stored public key
  (Web Crypto). The sign counter must be non-regressing.
- Challenges are 256-bit random, held in KV for 5 minutes, and deleted on use.

## What the server stores

- `users`: id (WebAuthn user handle), optional label, the recovery-wrapped DEK, and
  `recovery_lookup = SHA-256(recovery code)`.
- `credentials`: passkey public key, sign counter, and the PRF-wrapped DEK (unreadable to us).
- `notes`: `{id, ciphertext, iv, updated_at, deleted}` — ciphertext only.

No note plaintext and no usable key ever reach storage.

## Sessions

Stateless: `userId.exp.HMAC(SESSION_SECRET, "userId.exp")`, in an
`HttpOnly; Secure; SameSite=Lax` cookie, 30-day expiry. Tampering or expiry fails closed.

## Transport & content integrity

- Strict CSP (`public/_headers`): `script-src 'self'` — no third-party JavaScript anywhere,
  including next to decrypted notes. Ads are fetched server-side and rendered as first-party DOM.
- `X-Frame-Options: DENY`, `nosniff`, `no-referrer`, `frame-ancestors 'none'`, `base-uri 'none'`.

## Known limitations

- **Recovery code is the only backup.** Lose every passkey without it and notes are
  unrecoverable — inherent to zero-knowledge. The recovery code is itself a bearer secret:
  anyone with it can restore the account, so treat it like a master password.
- **Metadata** (note count, sizes, update times) is visible to the server. There is no email.
- **Last-write-wins** sync can drop a concurrent edit made offline on another device.
- **PRF cross-device** relies on the platform syncing the passkey (and its PRF secret). Adding
  a separate, non-synced passkey stores its own wrapped DEK copy.
- Client-side crypto trusts the delivered app code; a compromised host could serve malicious
  JS. The strict first-party CSP narrows this, but hosting integrity still matters.

## Reporting

Please report vulnerabilities privately to the maintainer rather than opening a public issue.
