/** Account page: show status, add another passkey, sign out. */
import { loadDek } from './notes.js';
import { register, passkeysSupported } from './passkey.js';
import { signOut } from './sync.js';

const infoEl = document.getElementById('accountInfo');
const addSection = document.getElementById('addPasskeySection');
const addBtn = document.getElementById('addPasskeyBtn');
const addMessage = document.getElementById('addMessage');
const signOutBtn = document.getElementById('signOutBtn');

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
  infoEl.innerHTML = `Signed in${me.label ? ` as <strong>${me.label}</strong>` : ''}. ${me.passkeys} passkey${me.passkeys === 1 ? '' : 's'} · notes sync across your devices.`;
  if (!passkeysSupported()) addSection.hidden = true;
}

addBtn.addEventListener('click', async () => {
  addMessage.innerHTML = '';
  addBtn.disabled = true;
  try {
    const dek = await loadDek();
    // authenticatedAdd: the server attaches this passkey to the current session.
    await register(dek, { authenticatedAdd: true });
    addMessage.innerHTML = '<div class="msg msg-ok">Passkey added. You can now sign in with it on this device.</div>';
    await render();
  } catch (e) {
    addMessage.innerHTML = `<div class="msg msg-err">${e.message || 'Could not add a passkey.'}</div>`;
  } finally {
    addBtn.disabled = false;
  }
});

signOutBtn.addEventListener('click', async () => {
  if (!confirm('Sign out and clear this device? Unsynced local notes will be removed.')) return;
  await signOut();
  location.replace('/app');
});

render();
