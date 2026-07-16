/** Username + passphrase E2E — no WebAuthn. Create on one context, sign in from
 *  another (simulating a different browser/device), notes decrypt. */
import puppeteer from 'puppeteer-core';
const BASE = 'http://localhost:8788';
const CHROME = '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome';
let pass = 0, fail = 0;
const check = (n, c) => { c ? (pass++, console.log(`  ok   ${n}`)) : (fail++, console.log(`  FAIL ${n}`)); };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const browser = await puppeteer.launch({ executablePath: CHROME, headless: 'new', args: ['--no-sandbox'] });
try {
  const username = `pwuser${Date.now()}`;
  const PASS = 'correct horse battery staple';

  // Context 1: anonymous note, then create a username+passphrase account.
  const c1 = await browser.createBrowserContext();
  const p1 = await c1.newPage();
  await p1.goto(`${BASE}/app`, { waitUntil: 'networkidle0' });
  await p1.waitForSelector('#editor');
  await p1.type('#editor', 'passphrase note alpha');
  await p1.waitForFunction(() => document.querySelector('#status').textContent === 'Saved');

  await p1.goto(`${BASE}/login`, { waitUntil: 'networkidle0' });
  await p1.click('#tabCreate');
  await p1.type('#cuUser', username);
  await p1.type('#cuPass', PASS);
  await p1.type('#cuPass2', PASS);
  await p1.click('#createBtn');
  await p1.waitForFunction(() => !document.querySelector('#recoveryBox').hidden, { timeout: 15000 });
  const recovery = await p1.$eval('#recoveryCode', (e) => e.textContent);
  check('account creation shows a recovery code', /^[A-Z0-9]{5}(-[A-Z0-9]{5}){3}$/.test(recovery));

  const me = await p1.evaluate(async () => (await fetch('/api/account/me')).json());
  check('account has the username set', me.username === username);
  const srv = await p1.evaluate(async () => (await fetch('/api/notes?since=0')).json());
  check('server holds 1 ciphertext note', srv.notes.length === 1 && !/passphrase note alpha/.test(srv.notes[0].ciphertext));

  // Context 2: a "different browser" — sign in with username + passphrase only.
  const c2 = await browser.createBrowserContext();
  const p2 = await c2.newPage();
  await p2.goto(`${BASE}/app`, { waitUntil: 'networkidle0' });
  await p2.goto(`${BASE}/login`, { waitUntil: 'networkidle0' });
  await p2.type('#siUser', username);
  await p2.type('#siPass', PASS);
  await p2.click('#signinBtn');
  await p2.waitForFunction(() => location.pathname === '/app', { timeout: 15000 });
  await sleep(1000);
  await p2.waitForSelector('.note-item');
  const titles = await p2.$$eval('.note-item h3', (e) => e.map((x) => x.textContent));
  check('second device decrypts notes via username+passphrase', titles.includes('passphrase note alpha'));

  // Context 3: wrong passphrase is rejected.
  const c3 = await browser.createBrowserContext();
  const p3 = await c3.newPage();
  await p3.goto(`${BASE}/login`, { waitUntil: 'networkidle0' });
  await p3.type('#siUser', username);
  await p3.type('#siPass', 'the wrong passphrase');
  await p3.click('#signinBtn');
  await p3.waitForFunction(() => /invalid username or passphrase/i.test(document.querySelector('#message').textContent || ''), { timeout: 10000 })
    .then(() => check('wrong passphrase is rejected', true))
    .catch(() => check('wrong passphrase is rejected', false));
} catch (e) {
  console.log('  FAIL exception:', e.message);
  fail++;
} finally {
  await browser.close();
}
console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
