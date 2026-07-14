# 🦎 Note Newt

**Take notes with you anywhere.** A frictionless, encrypted, installable notes PWA.
Open it and start typing — no signup. Add a **passkey** only when you want your notes to
sync across devices; accounts are **zero-knowledge by default** (no email, no password,
no server-side key).

Built on the same zero-build, near-zero-dependency Cloudflare stack as its sibling
[WhisperFox](https://whisperfox.pages.dev): static HTML + vanilla ES modules on Cloudflare
Pages, a handful of Pages Functions, D1, and KV. No framework, no bundler, no build step.

## What it does

- **Local-first.** The app opens straight into the editor. Notes are AES-256-GCM encrypted
  in the browser and stored in IndexedDB from the first keystroke. Works fully offline.
- **Passkey sync.** Create a passkey (Face ID / Touch ID / device PIN) to sync encrypted
  notes across devices — no email, no password. Your local notes migrate into the account.
- **Zero-knowledge by default.** The note key (DEK) is wrapped by a secret from the passkey's
  WebAuthn **PRF extension**, which never leaves your device — so the server stores only
  ciphertext it can't read. On browsers without PRF (e.g. Firefox) the key comes from a
  **passphrase** instead — same zero-knowledge envelope, chosen automatically. A one-time
  **recovery code** is your backup key.
- **Installable PWA.** Manifest + service worker; add to home screen, use offline.
- **Ad-supported, privacy-first.** Ads are fetched server-side and rendered as first-party
  DOM (no third-party JS, strict CSP) — never inside note content. No paid tier, no billing.

## Security model

Passkey accounts are **zero-knowledge**: the DEK (the one AES-256 key that encrypts notes)
is wrapped client-side under the passkey PRF secret and, separately, under a recovery code.
The server never receives the PRF secret or a usable key.

| | What the server holds |
|---|---|
| Notes | `{id, ciphertext, iv, updated_at, deleted}` — ciphertext only |
| Credentials | passkey **public** key, sign counter, and the **PRF-wrapped** DEK (unreadable) |
| Recovery | DEK wrapped under the recovery code + `sha256(recovery code)` for lookup |

Losing every passkey is recoverable **only** with the recovery code (that's the cost of
zero-knowledge). WebAuthn assertions are verified server-side with Web Crypto (ES256 / P-256).
See [SECURITY.md](SECURITY.md).

## Architecture

```
public/                 static site + PWA (deployed as-is by Cloudflare Pages)
  index.html            SEO landing (served at /)
  {no-signup-notes,private-notes-online,encrypted-notepad,privacy}.html   content pages
  app.html              the app shell (/app) — opens with NO login wall
  login.html/.js        opt-in: create / sign in with a passkey
  account.html/.js      sync status, add a passkey, sign out
  recover.html/.js      recover with the recovery code, then register a new passkey
  passkey.js            native WebAuthn (create/get) + PRF→key derivation
  crypto.js             Web Crypto: AES-GCM, PBKDF2, DEK wrap/unwrap (shared with Node tests)
  db.js                 IndexedDB wrapper (encrypted note blobs + kv bag)
  notes.js              local-first note model (encrypt/decrypt, CRUD)
  sync.js               login migration + push/pull (loaded only once an account exists)
  ad.js / footer.js     first-party ad renderer / shared cross-promo footer
  sw.js                 service worker (app-shell cache, offline)
  _headers              strict CSP + security headers
functions/
  _lib.js               HMAC/base64, sessions, SHA-256 (shared with Node tests)
  _webauthn.js          WebAuthn verification: CBOR, COSE→JWK, DER→raw sig, ES256 verify
  _http.js _auth.js     JSON + cookie helpers; session middleware
  api/auth/passkey/{register-options,register,login-options,login}.js
  api/auth/logout.js
  api/account/{me,recover}.js
  api/notes/index.js    GET ?since= (delta pull) · POST (bulk push, last-write-wins)
  api/ad.js             server-fetched ad decision + house-ad fallback
schema.sql              D1 tables (users, credentials, notes)
scripts/                selftest.mjs (crypto) · smoke.mjs (HTTP) · e2e.mjs (passkey, virtual authenticator)
```

- **Notes + accounts + credentials** live in **D1** (SQLite) — strongly consistent, queryable
  for delta sync.
- **WebAuthn challenges** live in **KV** (`pkchal:{challenge}`, 5-min TTL) — single-use.
- **Sessions** are stateless signed cookies (`HttpOnly; Secure; SameSite=Lax`, 30 days) — no
  session table.

## Local development

```bash
npm install
cp .dev.vars.example .dev.vars        # dev-only SESSION_SECRET (already gitignored)
npx wrangler d1 execute notenewt --local --file=schema.sql
npm run dev                           # http://localhost:8788
```

Passkeys work on `localhost` (a secure context). Just click **Create a passkey** — your OS
prompts for Touch ID / a device PIN, or use the browser's virtual authenticator devtools.

### Tests

```bash
npm run selftest   # crypto round-trips: note↔DEK, DEK wrap/unwrap, recovery, sessions (no network)
npm run smoke      # HTTP plumbing: challenge issuance, auth gating, static pages (needs `npm run dev`)
npm i --no-save puppeteer-core && npm run e2e   # passkey E2E via a Chrome virtual authenticator
```

## Deploy (Cloudflare Pages)

```bash
wrangler pages project create notenewt
wrangler d1 create notenewt                  # paste database_id into wrangler.toml
wrangler kv namespace create notenewt-tokens # paste id into wrangler.toml
wrangler d1 execute notenewt --remote --file=schema.sql
wrangler pages secret put SESSION_SECRET     # long random — the only secret
npm run deploy
```

Passkeys are bound to your domain (the WebAuthn RP id = the request hostname), so they work
per-origin automatically — no configuration. Set `ETHICALADS_PUBLISHER` (in `wrangler.toml`
`[vars]`) once approved; until then the first-party house ad serves. Rate-limit
`/api/*` at the Cloudflare edge (WAF rule + Bot Fight Mode).

## Open items

- **Production domain.** Canonical URLs/sitemap use `https://notenewt.com` — change if you deploy
  elsewhere (e.g. `notenewt.pages.dev`).
- **Real PNG app icons.** The manifest currently ships an SVG icon (fine on modern browsers);
  add 192/512 PNG + maskable variants for best install UX.
- **Sync conflicts.** v1 is last-write-wins per note by `updated_at`; per-note revisions/merge is
  a later improvement.
- **Passkey coverage.** Requires WebAuthn (broad on modern platforms). Where the PRF extension
  is unavailable (e.g. Firefox), the app transparently falls back to a passphrase-derived key,
  so those users can still create a syncing, zero-knowledge account.

MIT.
