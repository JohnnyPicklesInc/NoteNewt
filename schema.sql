-- Note Newt D1 schema (passkey / WebAuthn auth). Apply with:
--   wrangler d1 execute notenewt --local --file=schema.sql            (local)
--   wrangler d1 execute notenewt --remote --file=schema.sql           (production)
--
-- Accounts are passkey-based and zero-knowledge by default: the note key (DEK)
-- is wrapped with a secret derived from the passkey's WebAuthn PRF extension,
-- which never leaves the user's device. The server stores only public keys,
-- wrapped (unreadable) DEKs, and ciphertext notes.

CREATE TABLE IF NOT EXISTS users (
  id                    TEXT PRIMARY KEY,          -- user id (base64url); also a WebAuthn user handle
  created_at            INTEGER NOT NULL,          -- unix seconds
  label                 TEXT,                      -- optional display label for the account
  -- Username + passphrase backbone (works on any browser; passkeys are optional).
  -- The passphrase derives an auth secret (verified via pw_verifier) and a
  -- separate encryption key that wraps the DEK (pw_wrapped_dek). Zero-knowledge:
  -- the passphrase and the encryption key never reach the server.
  username              TEXT,
  pw_salt               TEXT,                      -- base64url PBKDF2 salt
  pw_verifier           TEXT,                      -- base64url SHA-256(authSecret)
  pw_wrapped_dek        TEXT,                      -- base64url DEK wrapped under the passphrase enc key
  pw_wrapped_dek_iv     TEXT,
  -- DEK wrapped under a recovery-code-derived key (the backup path if every
  -- passkey is lost). Set when the user saves a recovery code.
  recovery_wrapped_dek  TEXT,
  recovery_iv           TEXT,
  recovery_salt         TEXT,
  recovery_lookup       TEXT                       -- sha256(recovery code) for lookup on recovery
);
CREATE INDEX IF NOT EXISTS idx_users_recovery ON users (recovery_lookup);
-- Unique index (not an inline constraint) so ALTER can add it on existing DBs,
-- and so multiple NULL usernames are allowed (passkey-only accounts).
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_username ON users (username);

-- One row per passkey. A synced passkey (iCloud/Google) covers a user's devices
-- with one credential; additional devices add more rows.
CREATE TABLE IF NOT EXISTS credentials (
  credential_id  TEXT PRIMARY KEY,                 -- base64url raw credential id
  user_id        TEXT NOT NULL,
  pubkey_x       TEXT NOT NULL,                    -- base64url EC P-256 x
  pubkey_y       TEXT NOT NULL,                    -- base64url EC P-256 y
  alg            INTEGER NOT NULL,                 -- COSE alg (-7 = ES256)
  sign_count     INTEGER NOT NULL DEFAULT 0,
  -- How the DEK is wrapped for this credential (both are zero-knowledge):
  --   'prf'        : key from the passkey WebAuthn PRF extension (default)
  --   'passphrase' : key from PBKDF2(passphrase) — fallback for no-PRF browsers (Firefox)
  key_type       TEXT NOT NULL DEFAULT 'prf',
  dek_salt       TEXT,                             -- base64url PBKDF2 salt (passphrase mode only)
  -- The DEK wrapped under this credential's key (PRF- or passphrase-derived).
  wrapped_dek    TEXT NOT NULL,
  wrapped_dek_iv TEXT NOT NULL,
  created_at     INTEGER NOT NULL,
  FOREIGN KEY (user_id) REFERENCES users(id)
);
CREATE INDEX IF NOT EXISTS idx_credentials_user ON credentials (user_id);

CREATE TABLE IF NOT EXISTS notes (
  id          TEXT PRIMARY KEY,                    -- client-generated note id (uuid)
  user_id     TEXT NOT NULL,
  ciphertext  TEXT NOT NULL,                       -- base64url AES-GCM ciphertext
  iv          TEXT NOT NULL,                       -- base64url IV
  updated_at  INTEGER NOT NULL,                    -- unix ms (client clock, for LWW)
  deleted     INTEGER NOT NULL DEFAULT 0,          -- soft delete (tombstone syncs)
  FOREIGN KEY (user_id) REFERENCES users(id)
);
CREATE INDEX IF NOT EXISTS idx_notes_user_updated ON notes (user_id, updated_at);

-- Shared lists: standalone, link-shared, end-to-end-encrypted collaborative lists.
-- No account needed. The content key lives in the link fragment (or is derived
-- from a passphrase) and never reaches the server. Ownership is a capability:
-- owner_hash = SHA-256(owner secret); only the holder can lock/unlock/delete.
CREATE TABLE IF NOT EXISTS shared_lists (
  id             TEXT PRIMARY KEY,                 -- random public id (in the link)
  ciphertext     TEXT NOT NULL,                    -- base64url AES-GCM ciphertext of the list
  iv             TEXT NOT NULL,                    -- base64url IV
  version        INTEGER NOT NULL DEFAULT 1,       -- bumped per write (optimistic concurrency)
  locked         INTEGER NOT NULL DEFAULT 0,       -- 1 = read-only (owner lock)
  owner_hash     TEXT NOT NULL,                    -- base64url SHA-256(owner secret)
  has_passphrase INTEGER NOT NULL DEFAULT 0,       -- 1 = key derived from a passphrase
  pw_salt        TEXT,                             -- base64url PBKDF2 salt (passphrase mode)
  created_at     INTEGER NOT NULL,
  updated_at     INTEGER NOT NULL
);

-- Recent versions kept for one-click revert of vandalism (capped per list).
CREATE TABLE IF NOT EXISTS shared_list_versions (
  id          TEXT NOT NULL,
  version     INTEGER NOT NULL,
  ciphertext  TEXT NOT NULL,
  iv          TEXT NOT NULL,
  updated_at  INTEGER NOT NULL,
  PRIMARY KEY (id, version)
);
