-- Note Newt D1 schema (passkey / WebAuthn auth). Apply with:
--   wrangler d1 execute notenewt --local --file=schema.sql            (local)
--   wrangler d1 execute notenewt --remote --file=schema.sql           (production)
--
-- Accounts are passkey-based and zero-knowledge by default: the note key (DEK)
-- is wrapped with a secret derived from the passkey's WebAuthn PRF extension,
-- which never leaves the user's device. The server stores only public keys,
-- wrapped (unreadable) DEKs, and ciphertext notes.

CREATE TABLE IF NOT EXISTS users (
  id                    TEXT PRIMARY KEY,          -- WebAuthn user handle (base64url), also our user id
  created_at            INTEGER NOT NULL,          -- unix seconds
  label                 TEXT,                      -- optional display label for the account
  -- DEK wrapped under a recovery-code-derived key (the backup path if every
  -- passkey is lost). Set when the user saves a recovery code.
  recovery_wrapped_dek  TEXT,
  recovery_iv           TEXT,
  recovery_salt         TEXT,
  recovery_lookup       TEXT                       -- sha256(recovery code) for lookup on recovery
);
CREATE INDEX IF NOT EXISTS idx_users_recovery ON users (recovery_lookup);

-- One row per passkey. A synced passkey (iCloud/Google) covers a user's devices
-- with one credential; additional devices add more rows.
CREATE TABLE IF NOT EXISTS credentials (
  credential_id  TEXT PRIMARY KEY,                 -- base64url raw credential id
  user_id        TEXT NOT NULL,
  pubkey_x       TEXT NOT NULL,                    -- base64url EC P-256 x
  pubkey_y       TEXT NOT NULL,                    -- base64url EC P-256 y
  alg            INTEGER NOT NULL,                 -- COSE alg (-7 = ES256)
  sign_count     INTEGER NOT NULL DEFAULT 0,
  -- The DEK wrapped under THIS passkey's PRF-derived key (zero-knowledge).
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
