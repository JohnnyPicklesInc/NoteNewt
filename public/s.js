/** Shared-note viewer. The link is /s#<id>.<key>: the id fetches the ciphertext,
 *  the key (fragment only, never sent to the server) decrypts it locally. */
import { unb64u, aesDecrypt, webCryptoAvailable } from './crypto.js';

const statusEl = document.getElementById('shareStatus');
const contentEl = document.getElementById('shareContent');
const fail = (msg) => { statusEl.className = 'msg msg-err'; statusEl.textContent = msg; };

async function main() {
  if (!webCryptoAvailable()) return fail('This browser can’t decrypt shared notes (needs HTTPS).');
  const frag = decodeURIComponent(location.hash.replace(/^#/, ''));
  const dot = frag.indexOf('.');
  const id = dot > 0 ? frag.slice(0, dot) : '';
  const keyB64 = dot > 0 ? frag.slice(dot + 1) : '';
  if (!id || !keyB64) return fail('This link is incomplete — ask the sender for the full link.');

  let data;
  try {
    const r = await fetch(`/api/share/${encodeURIComponent(id)}`);
    data = await r.json();
    if (!r.ok) return fail(data.error || 'This shared note is unavailable.');
  } catch {
    return fail('Network error — please try again.');
  }

  let text;
  try {
    text = await aesDecrypt(unb64u(keyB64), unb64u(data.ivB64), unb64u(data.ciphertextB64));
  } catch {
    return fail('Could not decrypt this note — the link’s key may be wrong or corrupted.');
  }

  statusEl.hidden = true;
  contentEl.textContent = text; // rendered as plain text (white-space: pre-wrap in CSS)
  contentEl.hidden = false;
  const firstLine = text.split('\n').find((l) => l.trim());
  if (firstLine) document.title = `${firstLine.trim().slice(0, 60)} · Note Newt`;
}

main();
