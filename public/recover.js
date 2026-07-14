/** Recovery: unlock the DEK from a recovery code, then register a new passkey. */
import { pbkdf2, unwrapKey, unb64u } from './crypto.js';
import { setDek } from './notes.js';
import { register, passkeysSupported } from './passkey.js';
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

    // Register a new passkey for this device (session already set by /recover).
    if (passkeysSupported()) {
      try {
        await register(dek, { authenticatedAdd: true });
      } catch {
        /* they can add one later from the account page */
      }
    }
    await completeLogin(data.userId, dek);
    location.replace('/app');
  } catch {
    show('Network error — please try again.', 'msg-err');
  } finally {
    submitBtn.disabled = false;
    submitBtn.textContent = 'Recover';
  }
});
