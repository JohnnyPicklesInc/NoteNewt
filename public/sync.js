/**
 * Optional sync layer. Does nothing until the user opts into a passkey account.
 * Handles login completion + DEK reconciliation, pushing dirty local notes, and
 * pulling remote changes (last-write-wins by updatedAt).
 *
 * The server only ever receives ciphertext and a PRF-wrapped DEK it cannot open.
 */
import { allNoteRows, putNoteRow, getNoteRow, kvGet, kvSet, wipeLocal } from './db.js';
import { aesDecrypt, aesEncrypt, b64u, unb64u } from './crypto.js';
import { currentDek, setDek, loadDek } from './notes.js';

/** Re-encrypt every local note from the current DEK to a new DEK. */
async function reEncryptLocalTo(newDek) {
  const oldDek = currentDek();
  const rows = await allNoteRows();
  for (const row of rows) {
    let text;
    try {
      text = await aesDecrypt(oldDek, unb64u(row.iv), unb64u(row.ciphertext));
    } catch {
      continue;
    }
    const { iv, ct } = await aesEncrypt(newDek, text);
    await putNoteRow({ ...row, iv: b64u(iv), ciphertext: b64u(ct), dirty: 1 });
  }
  await setDek(newDek);
}

/**
 * Finish a fresh registration: the account DEK IS this device's local DEK (the
 * passkey wrapped it during register), so just record the account and sync.
 */
export async function completeRegistration(userId, label) {
  await loadDek();
  await kvSet('account', { userId, label: label || null });
  await pushDirty();
  await pull();
}

/**
 * Finish a login on a device: reconcile the account DEK (unwrapped via the
 * passkey PRF) with the local one, record the account, then sync.
 * @param {string} userId
 * @param {Uint8Array} accountDek
 */
export async function completeLogin(userId, accountDek) {
  await loadDek();
  if (b64u(currentDek()) !== b64u(accountDek)) {
    await reEncryptLocalTo(accountDek); // fold any local notes into the account key
  } else {
    await setDek(accountDek);
  }
  await kvSet('account', { userId });
  await pushDirty();
  await pull();
}

/** Push all dirty local notes to the server; clear the dirty flag on success. */
export async function pushDirty() {
  if (!(await kvGet('account'))) return;
  const dirty = (await allNoteRows()).filter((r) => r.dirty);
  if (!dirty.length) return;
  const payload = dirty.map((r) => ({
    id: r.id,
    ciphertext: r.ciphertext,
    iv: r.iv,
    updatedAt: r.updatedAt,
    deleted: r.deleted ? 1 : 0,
  }));
  const r = await fetch('/api/notes', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ notes: payload }),
  });
  if (!r.ok) throw new Error('push failed');
  for (const row of dirty) await putNoteRow({ ...row, dirty: 0 });
}

/** Pull remote changes since the last cursor; merge last-write-wins. */
export async function pull() {
  if (!(await kvGet('account'))) return;
  const since = (await kvGet('syncCursor')) || 0;
  const r = await fetch(`/api/notes?since=${since}`);
  if (!r.ok) throw new Error('pull failed');
  const { notes } = await r.json();
  let maxTs = since;
  for (const remote of notes) {
    maxTs = Math.max(maxTs, remote.updatedAt);
    const local = await getNoteRow(remote.id);
    if (!local || remote.updatedAt > local.updatedAt) {
      await putNoteRow({
        id: remote.id,
        ciphertext: remote.ciphertext,
        iv: remote.iv,
        updatedAt: remote.updatedAt,
        deleted: remote.deleted ? 1 : 0,
        dirty: 0,
      });
    }
  }
  await kvSet('syncCursor', maxTs);
}

/** Sign out: clear the server session and wipe this device's local data. */
export async function signOut() {
  try {
    await fetch('/api/auth/logout', { method: 'POST' });
  } catch {
    /* ignore */
  }
  await wipeLocal();
}
