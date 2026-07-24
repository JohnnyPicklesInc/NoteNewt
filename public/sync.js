/**
 * Optional sync layer. Does nothing until the user opts into a passkey account.
 * Handles login completion + DEK reconciliation, pushing dirty local notes, and
 * pulling remote changes (last-write-wins by updatedAt).
 *
 * The server only ever receives ciphertext and a PRF-wrapped DEK it cannot open.
 */
import { allNoteRows, putNoteRow, getNoteRow, kvGet, kvSet, wipeLocal, allListRefs, putListRef } from './db.js';
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

/**
 * Pull remote changes since the last cursor; merge last-write-wins, but never
 * silently drop a concurrent edit. If a note changed remotely AND has unpushed
 * local edits (dirty) with different content, the local version is preserved as
 * a "conflicted copy" note before the remote version is applied.
 * @returns {Promise<number>} the number of conflicts preserved.
 */
export async function pull() {
  if (!(await kvGet('account'))) return 0;
  const since = (await kvGet('syncCursor')) || 0;
  const r = await fetch(`/api/notes?since=${since}`);
  if (!r.ok) throw new Error('pull failed');
  const { notes } = await r.json();
  const dek = currentDek();
  let maxTs = since;
  let conflicts = 0;

  for (const remote of notes) {
    maxTs = Math.max(maxTs, remote.updatedAt);
    const local = await getNoteRow(remote.id);
    // Keep local only when it exists and is newer/equal (it'll push). A note we
    // don't have locally (new, or after a wipe) must always be applied.
    if (local && remote.updatedAt <= local.updatedAt) continue;

    // Remote is newer than a local copy. If that copy has unpushed local edits
    // that differ, it's a real conflict — save our version as a separate copy.
    if (local && local.dirty && dek) {
      try {
        const localText = await aesDecrypt(dek, unb64u(local.iv), unb64u(local.ciphertext));
        const remoteText = await aesDecrypt(dek, unb64u(remote.iv), unb64u(remote.ciphertext));
        if (localText !== remoteText && !local.deleted) {
          const copy = await aesEncrypt(dek, `⚠️ Conflicted copy — edited on another device\n\n${localText}`);
          await putNoteRow({
            id: crypto.randomUUID(),
            iv: b64u(copy.iv),
            ciphertext: b64u(copy.ct),
            updatedAt: Date.now(),
            deleted: 0,
            dirty: 1,
          });
          conflicts++;
        }
      } catch {
        /* if we can't decrypt to compare, fall through and take remote */
      }
    }

    await putNoteRow({
      id: remote.id,
      ciphertext: remote.ciphertext,
      iv: remote.iv,
      updatedAt: remote.updatedAt,
      deleted: remote.deleted ? 1 : 0,
      dirty: 0,
    });
  }
  await kvSet('syncCursor', maxTs);
  return conflicts;
}

/**
 * Sync the encrypted bundle of shared-list references so a user's shared lists
 * follow them across devices. Pull → merge by id (newest wins, tombstones honored)
 * → write local → push the union. Convergent across devices. Requires the DEK.
 * @returns {Promise<Array|undefined>} the merged refs (undefined if not signed in).
 */
export async function syncListRefs() {
  if (!(await kvGet('account'))) return undefined;
  const dek = currentDek();
  if (!dek) return undefined;

  let remote = [];
  try {
    const r = await fetch('/api/list-refs');
    if (r.status === 401) return undefined;
    if (r.ok) {
      const d = await r.json();
      if (d && d.ciphertextB64) remote = JSON.parse(await aesDecrypt(dek, unb64u(d.ivB64), unb64u(d.ciphertextB64)));
    }
  } catch {
    return undefined; // offline
  }

  const byId = new Map();
  for (const row of await allListRefs()) byId.set(row.id, row);
  for (const row of Array.isArray(remote) ? remote : []) {
    const ex = byId.get(row.id);
    if (!ex || (row.updatedAt || 0) > (ex.updatedAt || 0)) byId.set(row.id, row);
  }
  const merged = [...byId.values()];
  for (const row of merged) await putListRef(row);

  try {
    const { iv, ct } = await aesEncrypt(dek, JSON.stringify(merged));
    const updatedAt = merged.reduce((m, r) => Math.max(m, r.updatedAt || 0), 0) || Date.now();
    await fetch('/api/list-refs', {
      method: 'PUT',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ ciphertextB64: b64u(ct), ivB64: b64u(iv), updatedAt }),
    });
  } catch {
    /* offline — will re-push next time */
  }
  return merged;
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
