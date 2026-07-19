/**
 * Note model for Note Newt — local-first. Every note is encrypted with the
 * device DEK before it touches IndexedDB; this module is the only place that
 * holds plaintext (in memory, transiently).
 *
 * A note's plaintext is a single UTF-8 string. The title is the first non-empty
 * line; the preview is what follows. Rows are marked `dirty` on every change so
 * the (optional) sync layer can push them once an account exists.
 */
import { kvGet, kvSet, putNoteRow, getNoteRow, allNoteRows } from './db.js';
import {
  generateDek,
  aesEncrypt,
  aesDecrypt,
  b64u,
  unb64u,
} from './crypto.js';

let dek = null; // Uint8Array, cached for the session

/**
 * Load the device DEK, minting one on first ever use. Fully local — no network.
 * @returns {Promise<Uint8Array>}
 */
export async function loadDek() {
  if (dek) return dek;
  const stored = await kvGet('dek');
  if (stored) {
    dek = unb64u(stored);
  } else {
    dek = generateDek();
    await kvSet('dek', b64u(dek));
  }
  return dek;
}

/**
 * Replace the device DEK (used during login → account migration). Callers are
 * responsible for re-encrypting or re-uploading notes as appropriate.
 * @param {Uint8Array} newDek
 */
export async function setDek(newDek) {
  dek = newDek;
  await kvSet('dek', b64u(newDek));
}

/** The current DEK bytes (must call loadDek first). @returns {Uint8Array|null} */
export function currentDek() {
  return dek;
}

function titleAndPreview(text) {
  const lines = String(text || '').split('\n');
  let title = '';
  let rest = [];
  for (let i = 0; i < lines.length; i++) {
    if (title === '' && lines[i].trim() !== '') {
      title = lines[i].trim();
      rest = lines.slice(i + 1);
      break;
    }
  }
  const preview = rest.join(' ').replace(/\s+/g, ' ').trim();
  return { title: title || 'Untitled note', preview };
}

async function decryptRow(row) {
  const text = await aesDecrypt(dek, unb64u(row.iv), unb64u(row.ciphertext));
  return { id: row.id, text, updatedAt: row.updatedAt };
}

async function encryptText(text) {
  const { iv, ct } = await aesEncrypt(dek, text);
  return { iv: b64u(iv), ciphertext: b64u(ct) };
}

/**
 * List notes for the sidebar, newest first, excluding tombstones. Each item
 * carries a lowercased `haystack` (full title+body) for client-side search.
 * @returns {Promise<Array<{id:string,title:string,preview:string,updatedAt:number,haystack:string}>>}
 */
export async function listNotes() {
  await loadDek();
  const rows = (await allNoteRows()).filter((r) => !r.deleted);
  const out = [];
  for (const row of rows) {
    try {
      const { text } = await decryptRow(row);
      out.push({ id: row.id, ...titleAndPreview(text), updatedAt: row.updatedAt, haystack: text.toLowerCase() });
    } catch {
      // A row we can't decrypt (e.g. wrong key after a bad migration) is skipped
      // rather than crashing the list.
    }
  }
  out.sort((a, b) => b.updatedAt - a.updatedAt);
  return out;
}

/** Decrypted text for one note, or '' if missing. @returns {Promise<string>} */
export async function getNoteText(id) {
  await loadDek();
  const row = await getNoteRow(id);
  if (!row || row.deleted) return '';
  const { text } = await decryptRow(row);
  return text;
}

/** Create a new empty note and return its id. @returns {Promise<string>} */
export async function createNote() {
  await loadDek();
  const id = crypto.randomUUID();
  const { iv, ciphertext } = await encryptText('');
  await putNoteRow({ id, iv, ciphertext, updatedAt: Date.now(), deleted: 0, dirty: 1 });
  return id;
}

/** Encrypt and persist a note's text. @returns {Promise<number>} the updatedAt stamp. */
export async function saveNote(id, text) {
  await loadDek();
  const { iv, ciphertext } = await encryptText(text);
  const updatedAt = Date.now();
  await putNoteRow({ id, iv, ciphertext, updatedAt, deleted: 0, dirty: 1 });
  return updatedAt;
}

/** Soft-delete a note (keeps a tombstone so the delete can sync). */
export async function softDelete(id) {
  const row = await getNoteRow(id);
  if (!row) return;
  await putNoteRow({ ...row, deleted: 1, dirty: 1, updatedAt: Date.now() });
}
