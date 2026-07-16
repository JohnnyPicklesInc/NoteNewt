/**
 * Passkey-accelerator E2E via Chrome's WebAuthn virtual authenticator (PRF).
 * Model: accounts are username+passphrase; a passkey is added for fast unlock.
 * Covers: create account, add a passkey, sign in with the passkey, and recovery.
 *
 * Requires a system Chrome and puppeteer-core (not a runtime dep):
 *   npm i --no-save puppeteer-core
 *   npm run dev        # in another terminal
 *   npm run e2e
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
  await client.send('WebAuthn.addVirtualAuthenticator', {
    options: { protocol: 'ctap2', ctap2Version: 'ctap2_1', transport: 'internal', hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true, hasPrf: true },
  });
}
async function clearLocal(page) {
  await page.evaluate(() => new Promise((res, rej) => {
    const req = indexedDB.open('notenewt');
    req.onsuccess = () => { const db = req.result; const tx = db.transaction(['kv', 'notes'], 'readwrite'); tx.objectStore('kv').clear(); tx.objectStore('notes').clear(); tx.oncomplete = () => { db.close(); res(); }; tx.onerror = () => rej(tx.error); };
    req.onerror = () => rej(req.error);
  }));
  const cookies = await page.cookies(); if (cookies.length) await page.deleteCookie(...cookies);
}

const browser = await puppeteer.launch({ executablePath: CHROME, headless: 'new', args: ['--no-sandbox'] });
try {
  const username = `pk${Date.now()}`;
  const PASS = 'correct horse battery staple';
  const p = await browser.newPage();
  await addAuthenticator(p);

  // Anonymous note, then create a username+passphrase account.
  await p.goto(`${BASE}/app`, { waitUntil: 'networkidle0' });
  await p.waitForSelector('#editor');
  await p.type('#editor', 'Passkey secret\nlaunch friday');
  await p.waitForFunction(() => document.querySelector('#status').textContent === 'Saved');
  await p.goto(`${BASE}/login`, { waitUntil: 'networkidle0' });
  await p.click('#tabCreate');
  await p.type('#cuUser', username);
  await p.type('#cuPass', PASS);
  await p.type('#cuPass2', PASS);
  await p.click('#createBtn');
  await p.waitForFunction(() => !document.querySelector('#recoveryBox').hidden, { timeout: 15000 });
  const recovery = await p.$eval('#recoveryCode', (e) => e.textContent);
  check('account created with a recovery code', /^[A-Z0-9]{5}(-[A-Z0-9]{5}){3}$/.test(recovery));

  // Add a passkey (PRF) for fast unlock.
  await p.click('#addPasskeyBtn');
  await p.waitForFunction(() => /Passkey added/.test(document.querySelector('#addMsg').textContent || ''), { timeout: 15000 });
  const me = await p.evaluate(async () => (await fetch('/api/account/me')).json());
  check('account has 1 passkey + username', me.passkeys === 1 && me.username === username);

  // Fresh session: sign in with the passkey (PRF unwrap), notes decrypt.
  await clearLocal(p);
  await p.goto(`${BASE}/login`, { waitUntil: 'networkidle0' });
  await p.click('#passkeyBtn');
  await p.waitForFunction(() => location.pathname === '/app', { timeout: 15000 });
  await sleep(1000);
  await p.waitForSelector('.note-item');
  const t1 = await p.$$eval('.note-item h3', (e) => e.map((x) => x.textContent));
  check('passkey sign-in decrypts notes via PRF', t1.includes('Passkey secret'));

  // Recovery on a fresh context: recovery code signs in.
  const ctx = await browser.createBrowserContext();
  const p2 = await ctx.newPage();
  await p2.goto(`${BASE}/app`, { waitUntil: 'networkidle0' });
  await p2.goto(`${BASE}/recover`, { waitUntil: 'networkidle0' });
  await p2.type('#code', recovery);
  await p2.click('#recoverForm button[type=submit]');
  await p2.waitForFunction(() => location.pathname === '/account', { timeout: 15000 });
  const notes = await p2.evaluate(async () => (await fetch('/api/notes?since=0')).json());
  check('recovery code signs in and reaches the notes', notes.notes.length === 1);
} catch (e) {
  console.log('  FAIL exception:', e.message); fail++;
} finally { await browser.close(); }
console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
