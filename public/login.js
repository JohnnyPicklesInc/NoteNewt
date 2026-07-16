/** Login page. Primary: username + passphrase (works on any browser). Optional:
 *  a passkey for fast unlock where supported. */
import { registerWithPassphrase, loginWithPassphrase } from './passphrase-auth.js';
import { authenticate, register, passkeysSupported } from './passkey.js';
import { loadDek } from './notes.js';
import { completeRegistration, completeLogin } from './sync.js';

const $ = (id) => document.getElementById(id);
const tabSignin = $('tabSignin'), tabCreate = $('tabCreate');
const signinForm = $('signinForm'), createForm = $('createForm');
const message = $('message');
const recoveryBox = $('recoveryBox'), recoveryCodeEl = $('recoveryCode');
const addPasskeyBtn = $('addPasskeyBtn'), addMsg = $('addMsg'), recoveryDone = $('recoveryDone');
const passkeyBtn = $('passkeyBtn'), orLine = $('orLine');
const ppSection = $('passphraseSection'), ppPrompt = $('ppPrompt'), pp1 = $('pp1'), ppSubmit = $('ppSubmit'), ppMsg = $('ppMsg');

const show = (html, cls) => (message.innerHTML = `<div class="msg ${cls}">${html}</div>`);

if (!passkeysSupported()) {
  passkeyBtn.hidden = true;
  orLine.hidden = true;
}

// --- tabs ---
function setTab(create) {
  message.innerHTML = '';
  tabCreate.classList.toggle('active', create);
  tabSignin.classList.toggle('active', !create);
  createForm.hidden = !create;
  signinForm.hidden = create;
}
tabSignin.addEventListener('click', () => setTab(false));
tabCreate.addEventListener('click', () => setTab(true));

// --- passphrase prompt (only for a passkey credential that uses a passphrase) ---
function getPassphrase() {
  return new Promise((resolve) => {
    signinForm.hidden = true;
    message.innerHTML = '';
    ppMsg.innerHTML = '';
    pp1.value = '';
    ppPrompt.textContent = 'Enter your passphrase to unlock your notes on this device.';
    ppSection.hidden = false;
    pp1.focus();
    const onSubmit = () => {
      if (!pp1.value) return;
      ppSubmit.removeEventListener('click', onSubmit);
      ppSection.hidden = true;
      resolve(pp1.value);
    };
    ppSubmit.addEventListener('click', onSubmit);
  });
}

// --- sign in (username + passphrase) ---
signinForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  show('Signing in…', 'msg-ok');
  try {
    const { userId, dek } = await loginWithPassphrase($('siUser').value.trim(), $('siPass').value);
    await completeLogin(userId, dek);
    location.replace('/app');
  } catch (err) {
    show(err.message || 'Could not sign in.', 'msg-err');
  }
});

// --- sign in with a passkey ---
passkeyBtn.addEventListener('click', async () => {
  show('Follow your browser\'s prompt to use your passkey…', 'msg-ok');
  try {
    const { userId, dek } = await authenticate({ getPassphrase });
    await completeLogin(userId, dek);
    location.replace('/app');
  } catch (err) {
    signinForm.hidden = false;
    show(err.message || 'Could not sign in with a passkey.', 'msg-err');
  }
});

// --- create account (username + passphrase) ---
createForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  const username = $('cuUser').value.trim().toLowerCase();
  const p1 = $('cuPass').value, p2 = $('cuPass2').value;
  if (!/^[a-z0-9_.-]{3,32}$/.test(username)) return show('Username must be 3–32 chars: letters, numbers, . _ -', 'msg-err');
  if (p1.length < 8) return show('Use a passphrase of at least 8 characters.', 'msg-err');
  if (p1 !== p2) return show('Passphrases don\'t match.', 'msg-err');

  show('Creating your account…', 'msg-ok');
  try {
    const dek = await loadDek(); // protect this device's existing local notes' key
    const { userId, recoveryCode } = await registerWithPassphrase(username, p1, dek);
    await completeRegistration(userId);
    tabCreate.parentElement.hidden = true;
    createForm.hidden = true;
    message.innerHTML = '';
    recoveryCodeEl.textContent = recoveryCode;
    addPasskeyBtn.hidden = !passkeysSupported();
    recoveryBox.hidden = false;
  } catch (err) {
    show(err.message || 'Could not create your account.', 'msg-err');
  }
});

addPasskeyBtn.addEventListener('click', async () => {
  addMsg.innerHTML = '';
  addPasskeyBtn.disabled = true;
  try {
    const dek = await loadDek();
    await register(dek, { authenticatedAdd: true });
    addMsg.innerHTML = '<div class="msg msg-ok">Passkey added — you can use it to sign in faster on this device.</div>';
    addPasskeyBtn.hidden = true;
  } catch (err) {
    addMsg.innerHTML = `<div class="msg msg-err">${err.message || 'Could not add a passkey.'}</div>`;
    addPasskeyBtn.disabled = false;
  }
});

recoveryDone.addEventListener('click', () => location.replace('/app'));
