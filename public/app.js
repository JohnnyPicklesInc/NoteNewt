/**
 * Note Newt app controller. Local-first: opens straight into the editor, no
 * login. All persistence is encrypted IndexedDB via notes.js. The optional sync
 * layer (sync.js) is loaded lazily and only does anything once an account exists.
 */
import { listNotes, getNoteText, saveNote, softDelete, loadDek } from './notes.js';
import { webCryptoAvailable } from './crypto.js';
import { kvGet } from './db.js';
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
};

let currentId = null;
let pendingNew = false; // a new note not yet written to DB (stays out of sync until typed)
let saveTimer = null;
let syncTimer = null;
let sync = null; // lazily-loaded sync module, if an account exists

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

async function renderList() {
  const notes = await listNotes();
  els.list.textContent = '';
  els.emptyHint.hidden = notes.length > 0 || pendingNew;
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
  const wasPending = pendingNew;
  await saveNote(currentId, text);
  pendingNew = false;
  els.status.textContent = 'Saved';
  if (wasPending) {
    await renderList(); // new note now appears in the list
  } else {
    const li = els.list.querySelector(`.note-item[data-id="${currentId}"]`);
    if (li) {
      const firstLine = text.split('\n').find((l) => l.trim()) || 'Untitled note';
      li.querySelector('h3').textContent = firstLine.trim();
    }
  }
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
  const account = await kvGet('account');
  updateSyncButton(account);
  if (!account) return; // anonymous: nothing to sync
  try {
    sync = await import('./sync.js');
    await sync.pull();
    await renderList();
    await sync.pushDirty();
  } catch {
    /* sync is best-effort; offline is fine */
  }
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
  await loadDek();
  await renderList();

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
  window.addEventListener('beforeunload', () => {
    if (saveTimer && !(pendingNew && els.editor.value.trim() === '')) {
      saveNote(currentId, els.editor.value);
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
