/**
 * Shared-list page. The link is /l#<id>.<key> (or /l#<id> for passphrase lists,
 * or /l#<id>.<key>.<ownerSecret> for the owner link). The key/passphrase decrypts
 * the list locally; the server only ever holds ciphertext.
 *
 * Collaboration: edits PUT with the version they're based on (optimistic
 * concurrency). A concurrent edit → the server 409s and we line-merge both
 * versions (nothing dropped). A short poll keeps everyone in sync. The owner
 * (whoever holds the owner secret) can lock (read-only), undo, or delete.
 */
import { aesEncrypt, aesDecrypt, pbkdf2, b64u, unb64u, webCryptoAvailable } from './crypto.js';
import { kvGet, kvSet } from './db.js';

const $ = (id) => document.getElementById(id);
const statusEl = $('listStatus');
const stateEl = $('listState');
const editor = $('listEditor');
const passForm = $('passForm');
const passInput = $('passInput');
const passMsg = $('passMsg');
const ownerControls = $('ownerControls');
const lockBtn = $('lockBtn');
const undoBtn = $('undoBtn');
const deleteBtn = $('deleteListBtn');

let id, key, version = 0, locked = false, ownerSecretB64 = null, savedValue = '', meta = null;
let saveTimer = null;
let stopped = false;

const setState = (t) => { stateEl.textContent = t; };
const fail = (msg) => { statusEl.hidden = false; statusEl.className = 'msg msg-err'; statusEl.textContent = msg; editor.hidden = true; };

/** Union of lines: keep A's, append B's non-duplicate lines. Good for lists. */
function mergeLines(a, b) {
  const have = new Set(a.split('\n').map((s) => s.trim()).filter(Boolean));
  const extra = b.split('\n').filter((l) => l.trim() && !have.has(l.trim()));
  return extra.length ? `${a.replace(/\n+$/, '')}\n${extra.join('\n')}` : a;
}

function applyLocked() {
  editor.readOnly = locked;
  if (ownerControls && !ownerControls.hidden) lockBtn.textContent = locked ? 'Unlock (allow editing)' : 'Lock (make read-only)';
  if (locked) setState('Read-only (locked by owner)');
}

async function decryptRemote(g) {
  return aesDecrypt(key, unb64u(g.ivB64), unb64u(g.ciphertextB64));
}

async function openList() {
  const text = await decryptRemote(meta); // throws if key/passphrase wrong
  version = meta.version;
  locked = !!meta.locked;
  savedValue = text;
  statusEl.hidden = true;
  editor.value = text;
  editor.hidden = false;
  applyLocked();
  editor.addEventListener('input', scheduleSave);
  setupOwner();
  startPolling();
  setState(locked ? 'Read-only (locked by owner)' : 'Up to date');
}

function scheduleSave() {
  setState('Saving…');
  clearTimeout(saveTimer);
  saveTimer = setTimeout(() => save().catch(() => setState('Save failed')), 600);
}

async function save(retries = 2) {
  if (locked) return;
  const text = editor.value;
  if (text === savedValue) { setState('Up to date'); return; }
  const { iv, ct } = await aesEncrypt(key, text);
  let r;
  try {
    r = await fetch(`/api/list/${id}`, {
      method: 'PUT',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ ciphertextB64: b64u(ct), ivB64: b64u(iv), baseVersion: version }),
    });
  } catch {
    setState('Offline — will retry');
    return;
  }
  if (r.status === 200) {
    version = (await r.json()).version;
    savedValue = text;
    setState('Saved');
  } else if (r.status === 409 && retries > 0) {
    // Someone else edited. Merge both and retry against the new version.
    const g = await (await fetch(`/api/list/${id}`)).json();
    const remoteText = await decryptRemote(g);
    const merged = mergeLines(text, remoteText);
    editor.value = merged;
    version = g.version;
    setState('Merged others’ changes');
    await save(retries - 1);
  } else if (r.status === 423) {
    locked = true;
    applyLocked();
  } else {
    setState('Save failed');
  }
}

let polling = false;
function startPolling() {
  if (polling) return;
  polling = true;
  setInterval(poll, 4000);
  document.addEventListener('visibilitychange', () => { if (!document.hidden) poll(); });
  window.addEventListener('focus', poll);
}

async function poll() {
  if (stopped || document.hidden || !key) return;
  let r, g;
  try {
    r = await fetch(`/api/list/${id}`);
    g = await r.json();
  } catch {
    return;
  }
  if (r.status === 404) { stopped = true; fail('This list was deleted.'); return; }
  if (g.error) return;

  if (!!g.locked !== locked) { locked = !!g.locked; applyLocked(); }
  if (g.version > version) {
    const remoteText = await decryptRemote(g);
    if (editor.value === savedValue) {
      editor.value = remoteText;
      savedValue = remoteText;
      version = g.version;
      setState('Updated');
    } else {
      editor.value = mergeLines(editor.value, remoteText);
      version = g.version;
      scheduleSave();
    }
  }
}

// --- owner controls ----------------------------------------------------------

function setupOwner() {
  if (!ownerSecretB64) return;
  ownerControls.hidden = false;
  applyLocked();
  lockBtn.addEventListener('click', () => ownerAction('lock', { locked: !locked }));
  undoBtn.addEventListener('click', () => ownerAction('restore', { toVersion: version - 1 }));
  deleteBtn.addEventListener('click', () => {
    if (confirm('Delete this shared list for everyone? This cannot be undone.')) ownerAction('delete', {});
  });
}

async function ownerAction(kind, extra) {
  let r;
  try {
    r = await fetch(`/api/list/${id}/${kind}`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ ownerSecretB64, ...extra }),
    });
  } catch {
    setState('Network error');
    return;
  }
  const data = await r.json().catch(() => ({}));
  if (!r.ok) { setState(data.error || 'Action failed'); return; }
  if (kind === 'lock') { locked = !!data.locked; applyLocked(); }
  else if (kind === 'delete') { stopped = true; editor.hidden = true; ownerControls.hidden = true; fail('List deleted.'); }
  else if (kind === 'restore') { await poll(); setState('Reverted'); }
}

// --- boot --------------------------------------------------------------------

async function boot() {
  if (!webCryptoAvailable()) return fail('Shared lists need a secure (HTTPS) connection.');
  const parts = decodeURIComponent(location.hash.replace(/^#/, '')).split('.');
  id = parts[0] || '';
  const keyB64 = parts[1] || '';
  const ownerFromLink = parts[2] || '';
  if (!id) return fail('This link is incomplete — ask the sender for the full link.');

  try {
    const r = await fetch(`/api/list/${encodeURIComponent(id)}`);
    meta = await r.json();
    if (!r.ok) return fail(meta.error || 'This list is unavailable.');
  } catch {
    return fail('Network error — please try again.');
  }

  ownerSecretB64 = ownerFromLink || (await kvGet(`listOwner:${id}`)) || null;
  if (ownerFromLink) await kvSet(`listOwner:${id}`, ownerFromLink);

  if (meta.hasPassphrase && !keyB64) {
    statusEl.hidden = true;
    passForm.hidden = false;
    passInput.focus();
    passForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      passMsg.innerHTML = '';
      try {
        key = await pbkdf2(passInput.value, unb64u(meta.pwSaltB64));
        await openList();
        passForm.hidden = true;
      } catch {
        passMsg.innerHTML = '<div class="msg msg-err">Wrong passphrase — try again.</div>';
      }
    });
    return;
  }

  try {
    key = unb64u(keyB64);
    await openList();
  } catch {
    fail('Could not decrypt this list — the link’s key may be wrong or corrupted.');
  }
}

boot();
