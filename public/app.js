/**
 * Note Newt app controller. Local-first: opens straight into the editor, no
 * login. All persistence is encrypted IndexedDB via notes.js. The optional sync
 * layer (sync.js) is loaded lazily and only does anything once an account exists.
 */
import { listNotes, getNoteText, saveNote, softDelete, loadDek } from './notes.js';
import { webCryptoAvailable, randomBytes, aesEncrypt, pbkdf2, b64u } from './crypto.js';
import { kvGet, kvSet } from './db.js';
import { renderAd } from './ad.js';

const els = {
  layout: document.getElementById('layout'),
  list: document.getElementById('noteList'),
  emptyHint: document.getElementById('emptyHint'),
  editor: document.getElementById('editor'),
  status: document.getElementById('status'),
  newBtn: document.getElementById('newBtn'),
  deleteBtn: document.getElementById('deleteBtn'),
  backBtn: document.getElementById('backBtn'),
  syncBtn: document.getElementById('syncBtn'),
  banner: document.getElementById('localOnlyBanner'),
  dismissBanner: document.getElementById('dismissBanner'),
  search: document.getElementById('searchBox'),
  exportBtn: document.getElementById('exportBtn'),
  importFile: document.getElementById('importFile'),
  shareListBtn: document.getElementById('shareListBtn'),
  listModal: document.getElementById('listModal'),
  listPassCheck: document.getElementById('listPassCheck'),
  listPass: document.getElementById('listPass'),
  listCreateBtn: document.getElementById('listCreateBtn'),
  listCreatePane: document.getElementById('listCreatePane'),
  listResult: document.getElementById('listResult'),
  listShareLink: document.getElementById('listShareLink'),
  listOwnerLink: document.getElementById('listOwnerLink'),
  listOpenLink: document.getElementById('listOpenLink'),
  listCopyShare: document.getElementById('listCopyShare'),
  listCopyOwner: document.getElementById('listCopyOwner'),
  listMsg: document.getElementById('listMsg'),
  listClose: document.getElementById('listClose'),
};

let currentId = null;
let pendingNew = false; // a new note not yet written to DB (stays out of sync until typed)
let savedValue = ''; // editor content as last loaded/saved — used to detect unsaved edits
let saveTimer = null;
let syncTimer = null;
let pollTimer = null; // periodic pull while an account is active
let sync = null; // lazily-loaded sync module, if an account exists
let nudgeAccount = null; // cached account state for the "local only" banner
let nudgeDismissed = false;
let lastNoteCount = 0;
let searchQuery = '';

function setView(view) {
  els.layout.dataset.view = view; // 'list' | 'editor' (matters on mobile)
}

function relTime(ts) {
  const s = Math.round((Date.now() - ts) / 1000);
  if (s < 60) return 'just now';
  const m = Math.round(s / 60);
  if (m < 60) return `${m}m ago`;
  const h = Math.round(m / 60);
  if (h < 24) return `${h}h ago`;
  return new Date(ts).toLocaleDateString();
}

/** Show the "saved only on this device" nudge for anonymous users with notes. */
function updateNudge() {
  if (!els.banner) return;
  els.banner.hidden = !!nudgeAccount || nudgeDismissed || lastNoteCount === 0;
}

function openListModal() {
  els.listMsg.innerHTML = '';
  els.listResult.hidden = true;
  els.listCreatePane.hidden = false;
  els.listPassCheck.checked = false;
  els.listPass.hidden = true;
  els.listPass.value = '';
  els.listModal.hidden = false;
}

/** Create a standalone shared list from the current note's text. */
async function createSharedList() {
  const text = els.editor.value;
  if (!text.trim()) { els.listMsg.innerHTML = '<div class="msg msg-err">Write something first.</div>'; return; }

  let key, keyLinkPart = '', hasPassphrase = false, pwSaltB64 = null;
  if (els.listPassCheck.checked) {
    if (els.listPass.value.length < 6) { els.listMsg.innerHTML = '<div class="msg msg-err">Use a passphrase of at least 6 characters.</div>'; return; }
    const salt = randomBytes(16);
    key = await pbkdf2(els.listPass.value, salt);
    hasPassphrase = true;
    pwSaltB64 = b64u(salt); // key stays OUT of the link
  } else {
    key = randomBytes(32);
    keyLinkPart = b64u(key);
  }

  const ownerSecret = randomBytes(32);
  const ownerHashB64 = b64u(new Uint8Array(await crypto.subtle.digest('SHA-256', ownerSecret)));
  const { iv, ct } = await aesEncrypt(key, text);

  els.listCreateBtn.disabled = true;
  els.listCreateBtn.textContent = 'Creating…';
  try {
    const r = await fetch('/api/list', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ ciphertextB64: b64u(ct), ivB64: b64u(iv), ownerHashB64, hasPassphrase, pwSaltB64 }),
    });
    const data = await r.json();
    if (!r.ok) { els.listMsg.innerHTML = `<div class="msg msg-err">${data.error || 'Could not create the list.'}</div>`; return; }

    await kvSet(`listOwner:${data.id}`, b64u(ownerSecret)); // remember ownership on this device
    const shareLink = `${location.origin}/l#${data.id}${keyLinkPart ? `.${keyLinkPart}` : ''}`;
    const ownerLink = `${location.origin}/l#${data.id}.${keyLinkPart}.${b64u(ownerSecret)}`;
    els.listShareLink.value = shareLink;
    els.listOwnerLink.value = ownerLink;
    els.listOpenLink.href = ownerLink; // open as owner
    els.listCreatePane.hidden = true;
    els.listResult.hidden = false;
    els.listMsg.innerHTML = hasPassphrase
      ? '<div class="msg msg-ok">Share the link and tell them the passphrase separately.</div>'
      : '';
  } catch {
    els.listMsg.innerHTML = '<div class="msg msg-err">Network error — please try again.</div>';
  } finally {
    els.listCreateBtn.disabled = false;
    els.listCreateBtn.textContent = 'Create shared list';
  }
}

async function copyField(field, btn) {
  field.select();
  try { await navigator.clipboard.writeText(field.value); } catch { document.execCommand('copy'); }
  const t = btn.textContent;
  btn.textContent = 'Copied!';
  setTimeout(() => { btn.textContent = t; }, 1500);
}

/** Download all notes as a re-importable JSON file. */
async function exportNotes() {
  const list = await listNotes();
  const notes = [];
  for (const n of list) notes.push({ text: await getNoteText(n.id), updatedAt: n.updatedAt });
  const payload = { app: 'notenewt', version: 1, notes };
  const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `notenewt-export-${new Date().toISOString().slice(0, 10)}.json`;
  a.click();
  URL.revokeObjectURL(url);
}

/** Import notes from a file. JSON exports merge as new notes; plain text/markdown
 *  imports as a single note. Never overwrites existing notes. */
async function importNotes(file) {
  const raw = await file.text();
  let texts = [];
  try {
    const data = JSON.parse(raw);
    const arr = Array.isArray(data) ? data : data.notes;
    if (Array.isArray(arr)) texts = arr.map((n) => (typeof n === 'string' ? n : n.text ?? ''));
    else throw new Error('not a notes export');
  } catch {
    texts = [raw]; // treat the whole file as one plain-text note
  }
  let count = 0;
  for (const t of texts) {
    if (!t || t.trim() === '') continue;
    await saveNote(crypto.randomUUID(), t);
    count++;
  }
  await renderList();
  scheduleSync();
  els.status.textContent = `Imported ${count} note${count === 1 ? '' : 's'}`;
}

/** Ask the browser to keep our storage (exempt it from automatic eviction). */
async function requestPersistence() {
  try {
    if (navigator.storage?.persist && !(await navigator.storage.persisted())) {
      await navigator.storage.persist();
    }
  } catch {
    /* best-effort */
  }
}

async function renderList() {
  const all = await listNotes();
  lastNoteCount = all.length;
  updateNudge();
  const q = searchQuery.trim().toLowerCase();
  const notes = q ? all.filter((n) => n.haystack.includes(q)) : all;
  els.list.textContent = '';
  els.emptyHint.hidden = all.length > 0 || pendingNew;
  if (q && notes.length === 0) {
    const li = document.createElement('li');
    li.className = 'search-empty';
    li.textContent = `No notes match “${searchQuery.trim()}”.`;
    els.list.appendChild(li);
    return;
  }
  for (const n of notes) {
    const li = document.createElement('li');
    li.className = 'note-item' + (n.id === currentId ? ' active' : '');
    li.dataset.id = n.id;
    const h = document.createElement('h3');
    h.textContent = n.title;
    const p = document.createElement('p');
    p.textContent = n.preview || relTime(n.updatedAt);
    li.append(h, p);
    li.addEventListener('click', () => openNote(n.id));
    els.list.appendChild(li);
  }
}

async function openNote(id) {
  await flushSave();
  currentId = id;
  pendingNew = false;
  els.editor.value = await getNoteText(id);
  savedValue = els.editor.value;
  els.deleteBtn.hidden = false;
  els.status.textContent = 'Saved';
  setView('editor');
  await renderList();
  els.editor.focus();
}

function newNote() {
  // A fresh, blank note held only in memory — nothing is persisted (or synced)
  // until the user actually types something (see flushSave).
  currentId = crypto.randomUUID();
  pendingNew = true;
  els.editor.value = '';
  savedValue = '';
  els.deleteBtn.hidden = false;
  els.status.textContent = '';
  setView('editor');
  els.editor.focus();
}

function scheduleSave() {
  els.status.textContent = 'Saving…';
  clearTimeout(saveTimer);
  saveTimer = setTimeout(flushSave, 400);
}

async function flushSave() {
  clearTimeout(saveTimer);
  saveTimer = null;
  if (currentId == null) return;
  const text = els.editor.value;
  if (pendingNew && text.trim() === '') {
    els.status.textContent = '';
    return; // don't persist an untouched blank note
  }
  if (!pendingNew && text === savedValue) {
    els.status.textContent = 'Saved';
    return; // nothing changed — don't re-save (which would bump order on mere navigation)
  }
  pendingNew = false;
  savedValue = text;
  await saveNote(currentId, text); // stamps a fresh updatedAt
  els.status.textContent = 'Saved';
  await renderList(); // a real edit bumps this note to the top of the list, live
  scheduleSync();
}

async function deleteCurrent() {
  if (currentId == null) return;
  if (pendingNew) {
    // never persisted — just discard
    pendingNew = false;
    currentId = null;
    els.editor.value = '';
    els.deleteBtn.hidden = true;
    setView('list');
    await renderList();
    return;
  }
  if (!confirm('Delete this note?')) return;
  await softDelete(currentId);
  currentId = null;
  els.editor.value = '';
  els.deleteBtn.hidden = true;
  setView('list');
  await renderList();
  scheduleSync();
}

// --- optional sync -----------------------------------------------------------

async function initSync() {
  let account = await kvGet('account');
  // Reconcile: we may have a valid server session but no local record (signed in
  // on another browser/profile, or local data cleared). Ask the server.
  if (!account && navigator.onLine) {
    try {
      const r = await fetch('/api/account/me');
      if (r.ok) {
        const me = await r.json();
        account = { userId: me.userId, label: me.username || null };
        await kvSet('account', account);
      }
    } catch {
      /* offline — treat as anonymous for now */
    }
  }
  nudgeAccount = account;
  updateSyncButton(account);
  await renderList(); // reflect signed-in state in the banner immediately
  if (!account) return; // anonymous: nothing to sync
  try {
    sync = await import('./sync.js');
    const conflicts = await sync.pull();
    await renderList();
    await sync.pushDirty();
    startPolling();
    if (conflicts) noteConflicts(conflicts);
  } catch {
    /* sync is best-effort; offline is fine */
  }
}

/** Pull remote changes and reflect them live, without disturbing active edits. */
async function pollSync() {
  if (!sync || document.hidden) return;
  try {
    const conflicts = await sync.pull();
    await renderList();
    await refreshOpenNote();
    if (conflicts) noteConflicts(conflicts);
  } catch {
    /* offline — try again next tick */
  }
}

/** Surface preserved-conflict copies to the user. */
function noteConflicts(n) {
  els.status.textContent = `⚠️ ${n} conflicting edit${n === 1 ? '' : 's'} saved as a copy`;
}

/** If the open note changed remotely and the user has no unsaved edits, update it. */
async function refreshOpenNote() {
  if (currentId == null || pendingNew) return;
  if (saveTimer !== null) return; // a save is pending — don't stomp it
  if (els.editor.value !== savedValue) return; // user has unsaved edits — leave them be
  const latest = await getNoteText(currentId);
  if (latest !== els.editor.value) {
    els.editor.value = latest;
    savedValue = latest;
  }
}

let pollingStarted = false;
function startPolling() {
  if (pollingStarted) return;
  pollingStarted = true;
  pollTimer = setInterval(pollSync, 10000); // every 10s while the tab is visible
  // Also pull immediately when the user returns to the tab or reconnects.
  document.addEventListener('visibilitychange', () => { if (!document.hidden) pollSync(); });
  window.addEventListener('focus', pollSync);
  window.addEventListener('online', pollSync);
}

function updateSyncButton(account) {
  if (account && account.userId) {
    els.syncBtn.textContent = '✓ Synced';
    els.syncBtn.href = '/account';
    els.syncBtn.title = account.label || 'Synced across your devices';
  } else {
    els.syncBtn.textContent = 'Sync';
    els.syncBtn.href = '/login';
  }
}

function scheduleSync() {
  if (!sync) return;
  clearTimeout(syncTimer);
  syncTimer = setTimeout(() => sync.pushDirty().catch(() => {}), 1500);
}

// --- boot --------------------------------------------------------------------

async function boot() {
  if (!webCryptoAvailable()) {
    els.status.textContent = 'Secure storage unavailable (needs HTTPS).';
    return;
  }
  requestPersistence(); // ask the browser not to auto-evict our storage
  nudgeDismissed = !!(await kvGet('nudgeDismissed'));
  nudgeAccount = await kvGet('account');

  await loadDek();
  await renderList();

  els.dismissBanner.addEventListener('click', () => {
    nudgeDismissed = true;
    els.banner.hidden = true;
    kvSet('nudgeDismissed', true).catch(() => {});
  });

  const wantsNew = new URLSearchParams(location.search).get('new') === '1';
  const notes = await listNotes();
  if (wantsNew || notes.length === 0) {
    newNote(); // first run or "New note" shortcut: blank editor, nothing persisted yet
  } else {
    setView('list'); // let the list show first; user picks a note
  }

  els.newBtn.addEventListener('click', async () => {
    await flushSave();
    newNote();
  });
  els.deleteBtn.addEventListener('click', deleteCurrent);
  els.backBtn.addEventListener('click', async () => {
    await flushSave();
    setView('list');
    await renderList();
  });
  els.editor.addEventListener('input', scheduleSave);
  els.search.addEventListener('input', () => {
    searchQuery = els.search.value;
    renderList();
  });
  els.shareListBtn.addEventListener('click', () => { flushSave(); openListModal(); });
  els.listClose.addEventListener('click', () => { els.listModal.hidden = true; });
  els.listModal.addEventListener('click', (e) => { if (e.target === els.listModal) els.listModal.hidden = true; });
  els.listPassCheck.addEventListener('change', () => { els.listPass.hidden = !els.listPassCheck.checked; if (els.listPassCheck.checked) els.listPass.focus(); });
  els.listCreateBtn.addEventListener('click', () => createSharedList().catch(() => { els.listMsg.innerHTML = '<div class="msg msg-err">Failed.</div>'; }));
  els.listCopyShare.addEventListener('click', () => copyField(els.listShareLink, els.listCopyShare));
  els.listCopyOwner.addEventListener('click', () => copyField(els.listOwnerLink, els.listCopyOwner));
  els.exportBtn.addEventListener('click', () => exportNotes().catch(() => {}));
  els.importFile.addEventListener('change', async () => {
    const file = els.importFile.files[0];
    if (file) await importNotes(file).catch(() => { els.status.textContent = 'Import failed'; });
    els.importFile.value = '';
  });
  window.addEventListener('beforeunload', () => {
    const text = els.editor.value;
    if (currentId != null && text !== savedValue && !(pendingNew && text.trim() === '')) {
      saveNote(currentId, text);
    }
  });

  if ('serviceWorker' in navigator) {
    navigator.serviceWorker.register('/sw.js').catch(() => {});
  }

  // Slim, first-party ad in the footer slot — never inside note content.
  renderAd(document.getElementById('adSlot'));

  initSync();
}

boot();
