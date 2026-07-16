/** Account page: show status, add another passkey, sign out. */
import { loadDek } from './notes.js';
import { register, passkeysSupported } from './passkey.js';
import { setPassphrase } from './passphrase-auth.js';
import { signOut } from './sync.js';
import { wipeLocal } from './db.js';

const infoEl = document.getElementById('accountInfo');
const addSection = document.getElementById('addPasskeySection');
const addBtn = document.getElementById('addPasskeyBtn');
const addMessage = document.getElementById('addMessage');
const signOutBtn = document.getElementById('signOutBtn');
const ppTitle = document.getElementById('ppTitle');
const ppDesc = document.getElementById('ppDesc');
const ppUserWrap = document.getElementById('ppUserWrap');
const ppForm = document.getElementById('ppForm');
const ppMsg = document.getElementById('ppMsg');
let hasUsername = false;

/** Fallback passphrase prompt for no-PRF browsers on this secondary path. */
async function promptPassphrase() {
  const p = window.prompt('Your browser needs a passphrase to encrypt your notes. Set one (at least 8 characters):');
  if (!p || p.length < 8) throw new Error('A passphrase of at least 8 characters is required.');
  return p;
}

async function render() {
  let me;
  try {
    const r = await fetch('/api/account/me');
    if (r.status === 401) {
      location.replace('/login');
      return;
    }
    me = await r.json();
  } catch {
    infoEl.textContent = 'Could not load your account (offline?).';
    return;
  }
  const uname = me.username ? ` as <strong>${me.username.replace(/[<>&]/g, '')}</strong>` : '';
  infoEl.innerHTML = `Signed in${uname}. ${me.passkeys} passkey${me.passkeys === 1 ? '' : 's'} · notes sync across your devices.`;
  if (!passkeysSupported()) addSection.hidden = true;

  // Passphrase section: "add" (no username yet) or "change" (has one).
  if (me.username) {
    ppTitle.textContent = 'Change passphrase';
    ppDesc.textContent = `Signed in as ${me.username}. Set a new passphrase for this account.`;
    ppUserWrap.hidden = true;
  } else {
    ppTitle.textContent = 'Add a username & passphrase';
    ppDesc.textContent = 'Sign in on any browser (including Firefox), not just devices with your passkey.';
    ppUserWrap.hidden = false;
  }
  hasUsername = !!me.username;
}

addBtn.addEventListener('click', async () => {
  addMessage.innerHTML = '';
  addBtn.disabled = true;
  try {
    const dek = await loadDek();
    // authenticatedAdd: the server attaches this passkey to the current session.
    // On no-PRF browsers, register() asks for a passphrase to protect the key.
    await register(dek, { authenticatedAdd: true, getPassphrase: promptPassphrase });
    addMessage.innerHTML = '<div class="msg msg-ok">Passkey added. You can now sign in with it on this device.</div>';
    await render();
  } catch (e) {
    addMessage.innerHTML = `<div class="msg msg-err">${e.message || 'Could not add a passkey.'}</div>`;
  } finally {
    addBtn.disabled = false;
  }
});

ppForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  ppMsg.innerHTML = '';
  const username = document.getElementById('ppUser').value.trim().toLowerCase();
  const p1 = document.getElementById('ppP1').value;
  const p2 = document.getElementById('ppP2').value;
  if (!hasUsername && !/^[a-z0-9_.-]{3,32}$/.test(username)) {
    ppMsg.innerHTML = '<div class="msg msg-err">Username must be 3–32 chars: letters, numbers, . _ -</div>';
    return;
  }
  if (p1.length < 8) { ppMsg.innerHTML = '<div class="msg msg-err">Use at least 8 characters.</div>'; return; }
  if (p1 !== p2) { ppMsg.innerHTML = '<div class="msg msg-err">Passphrases don\'t match.</div>'; return; }
  try {
    const dek = await loadDek();
    await setPassphrase(p1, dek, hasUsername ? undefined : username);
    ppMsg.innerHTML = '<div class="msg msg-ok">Saved. You can now sign in with your username &amp; passphrase on any browser.</div>';
    await render();
  } catch (err) {
    ppMsg.innerHTML = `<div class="msg msg-err">${err.message || 'Could not save.'}</div>`;
  }
});

signOutBtn.addEventListener('click', async () => {
  if (!confirm('Sign out and clear this device? Unsynced local notes will be removed.')) return;
  await signOut();
  location.replace('/app');
});

const deleteAccountBtn = document.getElementById('deleteAccountBtn');
const deleteMessage = document.getElementById('deleteMessage');
deleteAccountBtn.addEventListener('click', async () => {
  if (!confirm('Permanently delete your account, all synced notes, and all passkeys? This cannot be undone.')) return;
  deleteAccountBtn.disabled = true;
  try {
    const r = await fetch('/api/account/delete', { method: 'POST' });
    if (!r.ok) throw new Error();
    await wipeLocal(); // clear this device too
    location.replace('/');
  } catch {
    deleteMessage.innerHTML = '<div class="msg msg-err">Could not delete your account. Please retry.</div>';
    deleteAccountBtn.disabled = false;
  }
});

render();
