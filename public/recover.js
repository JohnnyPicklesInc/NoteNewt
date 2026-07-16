/** Recovery: unlock the DEK from a recovery code and sign in; the user then sets
 *  a new passphrase/passkey from the account page. */
import { pbkdf2, unwrapKey, unb64u } from './crypto.js';
import { setDek } from './notes.js';
import { completeLogin } from './sync.js';

const form = document.getElementById('recoverForm');
const codeEl = document.getElementById('code');
const submitBtn = document.getElementById('submitBtn');
const message = document.getElementById('message');
const show = (html, cls) => (message.innerHTML = `<div class="msg ${cls}">${html}</div>`);

form.addEventListener('submit', async (e) => {
  e.preventDefault();
  message.innerHTML = '';
  submitBtn.disabled = true;
  submitBtn.textContent = 'Recovering…';
  try {
    const r = await fetch('/api/account/recover', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ recoveryCode: codeEl.value.trim() }),
    });
    const data = await r.json();
    if (!r.ok) {
      show(data.error || 'Recovery failed.', 'msg-err');
      return;
    }

    // Derive the DEK from the recovery code + stored salt.
    let dek;
    try {
      const kek = await pbkdf2(codeEl.value.trim().toUpperCase(), unb64u(data.recovery.saltB64));
      dek = await unwrapKey(kek, unb64u(data.recovery.ivB64), unb64u(data.recovery.wrappedB64));
    } catch {
      show('That recovery code did not unlock your notes.', 'msg-err');
      return;
    }
    await setDek(dek);
    // Signed in via the recovery code. Set up a new passphrase/passkey from the
    // account page (a fresh session is already set).
    await completeLogin(data.userId, dek);
    location.replace('/account');
  } catch {
    show('Network error — please try again.', 'msg-err');
  } finally {
    submitBtn.disabled = false;
    submitBtn.textContent = 'Recover';
  }
});
