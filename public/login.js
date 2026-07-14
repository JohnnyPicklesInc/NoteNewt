/** Login page: create or use a passkey, then sync. On browsers without the
 *  passkey PRF extension (e.g. Firefox), the encryption key comes from a
 *  passphrase instead — prompted here. */
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

const ppSection = document.getElementById('passphraseSection');
const ppPrompt = document.getElementById('ppPrompt');
const pp1 = document.getElementById('pp1');
const pp2 = document.getElementById('pp2');
const ppSubmit = document.getElementById('ppSubmit');
const ppMsg = document.getElementById('ppMsg');

function show(html, cls) {
  message.innerHTML = `<div class="msg ${cls}">${html}</div>`;
}
function busy(on) {
  createBtn.disabled = on;
  signinBtn.disabled = on;
}

/**
 * Show the passphrase form and resolve with the entered value.
 * @param {'create'|'unlock'} mode create shows a confirm field + min length.
 * @returns {Promise<string>}
 */
function getPassphrase(mode) {
  return new Promise((resolve) => {
    controls.hidden = true;
    message.innerHTML = '';
    ppMsg.innerHTML = '';
    pp1.value = '';
    pp2.value = '';
    pp2.hidden = mode !== 'create';
    pp1.autocomplete = pp2.autocomplete = mode === 'create' ? 'new-password' : 'current-password';
    ppPrompt.textContent =
      mode === 'create'
        ? "Your browser doesn't support device-based encryption, so set a passphrase to protect your notes. You'll need it to unlock them on each device — keep it safe."
        : 'Enter your passphrase to unlock your notes on this device.';
    ppSection.hidden = false;
    pp1.focus();

    const onSubmit = () => {
      if (mode === 'create') {
        if (pp1.value.length < 8) {
          ppMsg.innerHTML = '<div class="msg msg-err">Use at least 8 characters.</div>';
          return;
        }
        if (pp1.value !== pp2.value) {
          ppMsg.innerHTML = '<div class="msg msg-err">Passphrases don\'t match.</div>';
          return;
        }
      } else if (!pp1.value) {
        return;
      }
      ppSubmit.removeEventListener('click', onSubmit);
      ppSection.hidden = true;
      resolve(pp1.value);
    };
    ppSubmit.addEventListener('click', onSubmit);
  });
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
    const { userId, recoveryCode } = await register(dek, { getPassphrase: () => getPassphrase('create') });
    await completeRegistration(userId);
    controls.hidden = true;
    recoveryCodeEl.textContent = recoveryCode;
    recoveryBox.hidden = false;
  } catch (e) {
    controls.hidden = false;
    show(e.message || 'Could not create a passkey.', 'msg-err');
  } finally {
    busy(false);
  }
});

signinBtn.addEventListener('click', async () => {
  show('Follow your browser\'s prompt to use your passkey…', 'msg-ok');
  busy(true);
  try {
    const { userId, dek } = await authenticate({ getPassphrase: () => getPassphrase('unlock') });
    await completeLogin(userId, dek);
    location.replace('/app');
  } catch (e) {
    controls.hidden = false;
    show(e.message || 'Could not sign in.', 'msg-err');
  } finally {
    busy(false);
  }
});

recoveryDone.addEventListener('click', () => location.replace('/app'));
