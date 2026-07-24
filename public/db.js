/**
 * Minimal IndexedDB wrapper for Note Newt. Object stores:
 *   - `notes`: encrypted note blobs { id, ciphertext, iv, updatedAt, deleted, dirty }
 *   - `kv`:    small key-value bag for the device DEK, sync cursor, account state
 *   - `lists`: references to shared lists you created { id, keyB64, ownerSecretB64,
 *              hasPassphrase, title, createdAt } so they stay findable in the app
 *
 * Everything here is local + offline. Note plaintext is never stored — only
 * AES-GCM ciphertext (see crypto.js / notes.js).
 */

const DB_NAME = 'notenewt';
const DB_VERSION = 2;

let dbPromise = null;

function openDb() {
  if (dbPromise) return dbPromise;
  dbPromise = new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains('notes')) {
        db.createObjectStore('notes', { keyPath: 'id' });
      }
      if (!db.objectStoreNames.contains('kv')) {
        db.createObjectStore('kv', { keyPath: 'key' });
      }
      if (!db.objectStoreNames.contains('lists')) {
        db.createObjectStore('lists', { keyPath: 'id' });
      }
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
  return dbPromise;
}

function tx(store, mode) {
  return openDb().then((db) => db.transaction(store, mode).objectStore(store));
}

function reqToPromise(request) {
  return new Promise((resolve, reject) => {
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

// --- notes store -------------------------------------------------------------

export async function putNoteRow(row) {
  const store = await tx('notes', 'readwrite');
  return reqToPromise(store.put(row));
}

export async function getNoteRow(id) {
  const store = await tx('notes', 'readonly');
  return reqToPromise(store.get(id));
}

export async function allNoteRows() {
  const store = await tx('notes', 'readonly');
  return reqToPromise(store.getAll());
}

export async function deleteNoteRow(id) {
  const store = await tx('notes', 'readwrite');
  return reqToPromise(store.delete(id));
}

// --- kv store ----------------------------------------------------------------

export async function kvGet(key) {
  const store = await tx('kv', 'readonly');
  const row = await reqToPromise(store.get(key));
  return row ? row.value : undefined;
}

export async function kvSet(key, value) {
  const store = await tx('kv', 'readwrite');
  return reqToPromise(store.put({ key, value }));
}

export async function kvDelete(key) {
  const store = await tx('kv', 'readwrite');
  return reqToPromise(store.delete(key));
}

// --- shared-list references --------------------------------------------------

export async function putListRef(ref) {
  const store = await tx('lists', 'readwrite');
  return reqToPromise(store.put(ref));
}

export async function allListRefs() {
  const store = await tx('lists', 'readonly');
  return reqToPromise(store.getAll());
}

export async function deleteListRef(id) {
  const store = await tx('lists', 'readwrite');
  return reqToPromise(store.delete(id));
}

/** Wipe local notes + account (used on sign-out). Shared-list references are
 *  kept — they're independent capability objects, not tied to the account, so
 *  clearing them would lose access to lists you created. */
export async function wipeLocal() {
  const db = await openDb();
  await Promise.all(
    ['notes', 'kv'].map(
      (name) =>
        new Promise((resolve, reject) => {
          const r = db.transaction(name, 'readwrite').objectStore(name).clear();
          r.onsuccess = () => resolve();
          r.onerror = () => reject(r.error);
        }),
    ),
  );
}
