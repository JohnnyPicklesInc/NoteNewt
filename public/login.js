/** Login page: create or use a passkey, then sync. */
import { register, authenticate, passkeysSupported } from './passkey.js';
import { loadDek } from './notes.js';
import { completeRegistration, completeLogin } from './sync.js';

const controls = document.getElementById('controls');
const createBtn = document.getElementById('createBtn');
const signinBtn = document.getElementById('signinBtn');
const message = document.getElementById('message');
const recoveryBox = document.getElementById('recoveryBox');
const recoveryCodeEl = document.getElementById('recoveryCode');
const recoveryDone = document.getElementById('recoveryDone');

function show(html, cls) {
  message.innerHTML = `<div class="msg ${cls}">${html}</div>`;
}
function busy(on) {
  createBtn.disabled = on;
  signinBtn.disabled = on;
}

if (!passkeysSupported()) {
  controls.hidden = true;
  show('This browser doesn\'t support passkeys. Your notes still work locally on this device.', 'msg-err');
}

createBtn.addEventListener('click', async () => {
  show('Follow your browser\'s prompt to create a passkey…', 'msg-ok');
  busy(true);
  try {
    const dek = await loadDek(); // protect this device's existing local notes' key
    const { userId, recoveryCode } = await register(dek);
    await completeRegistration(userId);
    // Show the recovery code before leaving.
    controls.hidden = true;
    recoveryCodeEl.textContent = recoveryCode;
    recoveryBox.hidden = false;
  } catch (e) {
    show(e.message || 'Could not create a passkey.', 'msg-err');
  } finally {
    busy(false);
  }
});

signinBtn.addEventListener('click', async () => {
  show('Follow your browser\'s prompt to use your passkey…', 'msg-ok');
  busy(true);
  try {
    const { userId, dek } = await authenticate();
    await completeLogin(userId, dek);
    location.replace('/app');
  } catch (e) {
    show(e.message || 'Could not sign in.', 'msg-err');
  } finally {
    busy(false);
  }
});

recoveryDone.addEventListener('click', () => location.replace('/app'));
