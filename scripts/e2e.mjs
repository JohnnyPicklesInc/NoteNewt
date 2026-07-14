/**
 * Passkey E2E via Chrome's WebAuthn virtual authenticator (with PRF).
 * Covers: register (new account), PRF login after a local wipe, and recovery.
 *
 * Requires a system Chrome and puppeteer-core (not a runtime dep):
 *   npm i --no-save puppeteer-core
 *   npm run dev        # in another terminal
 *   npm run e2e
 * Override the Chrome path with CHROME_PATH if needed.
 */
import puppeteer from 'puppeteer-core';
const BASE = process.env.BASE_URL || 'http://localhost:8788';
const CHROME = process.env.CHROME_PATH || '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome';
let pass = 0, fail = 0;
const check = (n, c) => { c ? (pass++, console.log(`  ok   ${n}`)) : (fail++, console.log(`  FAIL ${n}`)); };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function addAuthenticator(page) {
  const client = await page.createCDPSession();
  await client.send('WebAuthn.enable');
  const { authenticatorId } = await client.send('WebAuthn.addVirtualAuthenticator', {
    options: {
      protocol: 'ctap2', ctap2Version: 'ctap2_1', transport: 'internal',
      hasResidentKey: true, hasUserVerification: true, isUserVerified: true,
      automaticPresenceSimulation: true, hasPrf: true,
    },
  });
  return { client, authenticatorId };
}

const browser = await puppeteer.launch({ executablePath: CHROME, headless: 'new', args: ['--no-sandbox'] });
try {
  // ---- Device 1: anonymous note, then create a passkey ----
  const p1 = await browser.newPage();
  await addAuthenticator(p1);
  await p1.goto(`${BASE}/app`, { waitUntil: 'networkidle0' });
  await p1.waitForSelector('#editor');
  await p1.type('#editor', 'Passkey secret\nonly my device holds the key');
  await p1.waitForFunction(() => document.querySelector('#status').textContent === 'Saved');

  await p1.goto(`${BASE}/login`, { waitUntil: 'networkidle0' });
  await p1.click('#createBtn');
  await p1.waitForFunction(() => !document.querySelector('#recoveryBox').hidden, { timeout: 15000 });
  const recovery = await p1.$eval('#recoveryCode', (e) => e.textContent);
  check('registration shows a recovery code', /^[A-Z0-9]{5}(-[A-Z0-9]{5}){3}$/.test(recovery));

  const me = await p1.evaluate(async () => (await fetch('/api/account/me')).json());
  check('account has exactly one passkey', me.passkeys === 1);
  const srv = await p1.evaluate(async () => (await fetch('/api/notes?since=0')).json());
  check('server holds 1 ciphertext note', srv.notes.length === 1 && !/Passkey secret/.test(srv.notes[0].ciphertext));

  // ---- Same device, fresh session: clear local data, sign in with the passkey (PRF unwrap) ----
  await p1.evaluate(() => new Promise((resolve, reject) => {
    const req = indexedDB.open('notenewt');
    req.onsuccess = () => {
      const db = req.result;
      const tx = db.transaction(['kv', 'notes'], 'readwrite');
      tx.objectStore('kv').clear();
      tx.objectStore('notes').clear();
      tx.oncomplete = () => { db.close(); resolve(); };
      tx.onerror = () => reject(tx.error);
    };
    req.onerror = () => reject(req.error);
  }));
  const cookies = await p1.cookies();
  if (cookies.length) await p1.deleteCookie(...cookies);
  await p1.goto(`${BASE}/login`, { waitUntil: 'networkidle0' });
  await p1.click('#signinBtn');
  await p1.waitForFunction(() => location.pathname === '/app', { timeout: 15000 });
  await sleep(1000);
  await p1.waitForSelector('.note-item', { timeout: 8000 });
  const titles1 = await p1.$$eval('.note-item h3', (els) => els.map((e) => e.textContent));
  check('passkey sign-in decrypts notes via PRF', titles1.includes('Passkey secret'));

  // ---- Recovery on a brand-new context (no passkey): recovery code unlocks notes ----
  const ctx = await browser.createBrowserContext();
  const p2 = await ctx.newPage();
  await addAuthenticator(p2); // so recovery can also register a fresh passkey
  await p2.goto(`${BASE}/app`, { waitUntil: 'networkidle0' });
  await p2.goto(`${BASE}/recover`, { waitUntil: 'networkidle0' });
  await p2.type('#code', recovery);
  await p2.click('#recoverForm button[type=submit]');
  await p2.waitForFunction(() => location.pathname === '/app', { timeout: 15000 });
  await sleep(1000);
  await p2.waitForSelector('.note-item', { timeout: 8000 });
  const titles2 = await p2.$$eval('.note-item h3', (els) => els.map((e) => e.textContent));
  check('recovery code restores + decrypts notes on a new device', titles2.includes('Passkey secret'));
  const me2 = await p2.evaluate(async () => (await fetch('/api/account/me')).json());
  check('recovery registered a new passkey (now 2)', me2.passkeys === 2);
} catch (e) {
  console.log('  FAIL exception:', e.message);
  fail++;
} finally {
  await browser.close();
}
console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
