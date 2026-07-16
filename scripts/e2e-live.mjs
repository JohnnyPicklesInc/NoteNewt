/**
 * Live-sync E2E (username + passphrase, no WebAuthn). Two devices on one account;
 * a note made on device 1 appears on already-open device 2 without a reload.
 *   npm i --no-save puppeteer-core && npm run dev && npm run e2e:live
 */
import puppeteer from 'puppeteer-core';
const BASE = process.env.BASE_URL || 'http://localhost:8788';
const CHROME = process.env.CHROME_PATH || '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome';
let pass = 0, fail = 0;
const check = (n, c) => { c ? (pass++, console.log(`  ok   ${n}`)) : (fail++, console.log(`  FAIL ${n}`)); };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const browser = await puppeteer.launch({ executablePath: CHROME, headless: 'new', args: ['--no-sandbox'] });
try {
  const username = `live${Date.now()}`;
  const PASS = 'correct horse battery staple';

  // Device 1: note + create account.
  const c1 = await browser.createBrowserContext();
  const p1 = await c1.newPage();
  await p1.goto(`${BASE}/app`, { waitUntil: 'networkidle0' });
  await p1.waitForSelector('#editor'); await p1.type('#editor', 'alpha note');
  await p1.waitForFunction(() => document.querySelector('#status').textContent === 'Saved');
  await p1.goto(`${BASE}/login`, { waitUntil: 'networkidle0' });
  await p1.click('#tabCreate');
  await p1.type('#cuUser', username); await p1.type('#cuPass', PASS); await p1.type('#cuPass2', PASS);
  await p1.click('#createBtn');
  await p1.waitForFunction(() => !document.querySelector('#recoveryBox').hidden, { timeout: 15000 });
  await p1.click('#recoveryDone');
  await p1.waitForFunction(() => location.pathname === '/app'); await sleep(500);

  // Device 2: sign in (same account), land on /app, idle.
  const c2 = await browser.createBrowserContext();
  const p2 = await c2.newPage();
  await p2.goto(`${BASE}/login`, { waitUntil: 'networkidle0' });
  await p2.type('#siUser', username); await p2.type('#siPass', PASS);
  await p2.click('#signinBtn');
  await p2.waitForFunction(() => location.pathname === '/app', { timeout: 15000 });
  await sleep(1000);
  await p2.waitForSelector('.note-item');
  const before = await p2.$$eval('.note-item h3', (e) => e.map((x) => x.textContent));
  check('device 2 starts with the alpha note', before.includes('alpha note'));

  // Device 1 adds a note while device 2 stays open.
  await p1.click('#newBtn');
  await p1.waitForFunction(() => document.querySelector('#editor').value === '');
  await p1.type('#editor', 'beta from device 1');
  await p1.waitForFunction(() => document.querySelector('#status').textContent === 'Saved');
  await sleep(2500); // debounced push

  // Device 2: returning to the tab -> immediate poll, no reload.
  await p2.evaluate(() => window.dispatchEvent(new Event('focus')));
  await p2.waitForFunction(
    () => [...document.querySelectorAll('.note-item h3')].some((h) => h.textContent === 'beta from device 1'),
    { timeout: 8000 },
  ).then(() => check('device 2 shows device 1\'s new note WITHOUT reload', true))
   .catch(() => check('device 2 shows device 1\'s new note WITHOUT reload', false));
} catch (e) {
  console.log('  FAIL exception:', e.message); fail++;
} finally { await browser.close(); }
console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
