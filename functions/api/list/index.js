/**
 * POST /api/list  { ciphertextB64, ivB64, ownerHashB64, hasPassphrase?, pwSaltB64? }
 *   -> { id, version }
 *
 * Creates a shared, end-to-end-encrypted list. No account needed. The content key
 * is never sent (it's in the link fragment or derived from a passphrase); the
 * server holds only ciphertext. Ownership is a capability: ownerHashB64 =
 * SHA-256(owner secret); only the secret's holder can later lock/delete.
 * Abuse is bounded by a size cap plus the edge rate limit.
 */
import { json } from '../../_http.js';
import { randomToken } from '../../_lib.js';

const MAX_CT = 300000; // ~220KB plaintext

export async function onRequestPost({ request, env }) {
  if (!env.DB) return json({ error: 'server misconfigured' }, 500);

  let b;
  try {
    b = await request.json();
  } catch {
    return json({ error: 'invalid json' }, 400);
  }
  const ct = String(b?.ciphertextB64 || '');
  const iv = String(b?.ivB64 || '');
  const ownerHash = String(b?.ownerHashB64 || '');
  if (!ct || !iv || !ownerHash) return json({ error: 'missing ciphertext/iv/owner' }, 400);
  if (ct.length > MAX_CT) return json({ error: 'list too large' }, 413);

  const hasPassphrase = b?.hasPassphrase ? 1 : 0;
  const pwSalt = hasPassphrase ? String(b?.pwSaltB64 || '') : null;
  if (hasPassphrase && !pwSalt) return json({ error: 'missing passphrase salt' }, 400);

  const id = randomToken(12);
  const now = Date.now();
  await env.DB.batch([
    env.DB.prepare(
      `INSERT INTO shared_lists (id, ciphertext, iv, version, locked, owner_hash, has_passphrase, pw_salt, created_at, updated_at)
       VALUES (?, ?, ?, 1, 0, ?, ?, ?, ?, ?)`,
    ).bind(id, ct, iv, ownerHash, hasPassphrase, pwSalt, now, now),
    env.DB.prepare('INSERT INTO shared_list_versions (id, version, ciphertext, iv, updated_at) VALUES (?, 1, ?, ?, ?)').bind(id, ct, iv, now),
  ]);

  return json({ id, version: 1 });
}
