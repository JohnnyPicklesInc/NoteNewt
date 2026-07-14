/** Passphrase-fallback E2E: a virtual authenticator WITHOUT PRF (simulates
 *  Firefox). Register must prompt for a passphrase; sign-in must ask for it and
 *  decrypt. */
import puppeteer from 'puppeteer-core';
const BASE = 'http://localhost:8788';
const CHROME = '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome';
let pass = 0, fail = 0;
const check = (n, c) => { c ? (pass++, console.log(`  ok   ${n}`)) : (fail++, console.log(`  FAIL ${n}`)); };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function addAuthenticator(page, hasPrf) {
  const client = await page.createCDPSession();
  await client.send('WebAuthn.enable');
  await client.send('WebAuthn.addVirtualAuthenticator', {
    options: {
      protocol: 'ctap2', ctap2Version: 'ctap2_1', transport: 'internal',
      hasResidentKey: true, hasUserVerification: true, isUserVerified: true,
      automaticPresenceSimulation: true, hasPrf,
    },
  });
}

const browser = await puppeteer.launch({ executablePath: CHROME, headless: 'new', args: ['--no-sandbox'] });
try {
  const PASS = 'firefox fallback pass';
  const p1 = await browser.newPage();
  await addAuthenticator(p1, false); // NO PRF
  await p1.goto(`${BASE}/app`, { waitUntil: 'networkidle0' });
  await p1.waitForSelector('#editor');
  await p1.type('#editor', 'No-PRF note\nencrypted by passphrase');
  await p1.waitForFunction(() => document.querySelector('#status').textContent === 'Saved');

  // Register — should fall back to a passphrase prompt.
  await p1.goto(`${BASE}/login`, { waitUntil: 'networkidle0' });
  await p1.click('#createBtn');
  await p1.waitForFunction(() => !document.querySelector('#passphraseSection').hidden, { timeout: 15000 });
  check('no-PRF registration prompts for a passphrase', true);
  await p1.type('#pp1', PASS);
  await p1.type('#pp2', PASS);
  await p1.click('#ppSubmit');
  await p1.waitForFunction(() => !document.querySelector('#recoveryBox').hidden, { timeout: 15000 });
  check('registration completes and shows recovery code', true);

  const srv = await p1.evaluate(async () => (await fetch('/api/notes?since=0')).json());
  check('server holds the note as ciphertext', srv.notes.length === 1 && !/No-PRF note/.test(srv.notes[0].ciphertext));

  // Wrong passphrase on sign-in must fail; correct must decrypt.
  await p1.evaluate(() => new Promise((res, rej) => {
    const req = indexedDB.open('notenewt');
    req.onsuccess = () => { const db = req.result; const tx = db.transaction(['kv', 'notes'], 'readwrite'); tx.objectStore('kv').clear(); tx.objectStore('notes').clear(); tx.oncomplete = () => { db.close(); res(); }; tx.onerror = () => rej(tx.error); };
    req.onerror = () => rej(req.error);
  }));
  const cookies = await p1.cookies(); if (cookies.length) await p1.deleteCookie(...cookies);

  await p1.goto(`${BASE}/login`, { waitUntil: 'networkidle0' });
  await p1.click('#signinBtn');
  await p1.waitForFunction(() => !document.querySelector('#passphraseSection').hidden, { timeout: 15000 });
  check('no-PRF sign-in prompts for the passphrase', true);
  await p1.type('#pp1', 'the wrong passphrase');
  await p1.click('#ppSubmit');
  await p1.waitForFunction(() => /Could not sign in|decrypt|unlock/i.test(document.querySelector('#message').textContent || ''), { timeout: 10000 });
  check('wrong passphrase is rejected', true);

  // correct passphrase
  await p1.click('#signinBtn');
  await p1.waitForFunction(() => !document.querySelector('#passphraseSection').hidden, { timeout: 15000 });
  await p1.type('#pp1', PASS);
  await p1.click('#ppSubmit');
  await p1.waitForFunction(() => location.pathname === '/app', { timeout: 15000 });
  await sleep(1000);
  await p1.waitForSelector('.note-item');
  const titles = await p1.$$eval('.note-item h3', (els) => els.map((e) => e.textContent));
  check('correct passphrase decrypts the note', titles.includes('No-PRF note'));
} catch (e) {
  console.log('  FAIL exception:', e.message);
  fail++;
} finally {
  await browser.close();
}
console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
