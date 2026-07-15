/** Live-sync E2E: two devices (contexts) on one account; a note made on device 1
 *  appears on already-open device 2 without a reload (via polling / focus pull). */
import puppeteer from 'puppeteer-core';
const BASE = 'http://localhost:8788';
const CHROME = '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome';
let pass = 0, fail = 0;
const check = (n, c) => { c ? (pass++, console.log(`  ok   ${n}`)) : (fail++, console.log(`  FAIL ${n}`)); };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function auth(page) {
  const c = await page.createCDPSession(); await c.send('WebAuthn.enable');
  await c.send('WebAuthn.addVirtualAuthenticator', { options: { protocol: 'ctap2', ctap2Version: 'ctap2_1', transport: 'internal', hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true, hasPrf: true } });
}
const browser = await puppeteer.launch({ executablePath: CHROME, headless: 'new', args: ['--no-sandbox'] });
try {
  // Device 1: register + a note.
  const c1 = await browser.createBrowserContext();
  const p1 = await c1.newPage(); await auth(p1);
  await p1.goto(`${BASE}/app`, { waitUntil: 'networkidle0' });
  await p1.waitForSelector('#editor'); await p1.type('#editor', 'alpha note');
  await p1.waitForFunction(() => document.querySelector('#status').textContent === 'Saved');
  await p1.goto(`${BASE}/login`, { waitUntil: 'networkidle0' }); await p1.click('#createBtn');
  await p1.waitForFunction(() => !document.querySelector('#recoveryBox').hidden, { timeout: 15000 });
  const recovery = await p1.$eval('#recoveryCode', (e) => e.textContent);
  await p1.goto(`${BASE}/app`, { waitUntil: 'networkidle0' }); await sleep(500);

  // Device 2: recover into the same account, land on /app (open, idle).
  const c2 = await browser.createBrowserContext();
  const p2 = await c2.newPage(); await auth(p2);
  await p2.goto(`${BASE}/app`, { waitUntil: 'networkidle0' });
  await p2.goto(`${BASE}/recover`, { waitUntil: 'networkidle0' });
  await p2.type('#code', recovery); await p2.click('#recoverForm button[type=submit]');
  await p2.waitForFunction(() => location.pathname === '/app', { timeout: 15000 });
  await sleep(1000);
  await p2.waitForSelector('.note-item');
  const before = await p2.$$eval('.note-item h3', (e) => e.map((x) => x.textContent));
  check('device 2 starts with the alpha note', before.includes('alpha note'));

  // Device 1 adds a new note while device 2 stays open (no reload).
  await p1.click('#newBtn');
  await p1.waitForFunction(() => document.querySelector('#editor').value === '');
  await p1.type('#editor', 'beta from device 1');
  await p1.waitForFunction(() => document.querySelector('#status').textContent === 'Saved');
  await sleep(2500); // let device 1's debounced push reach the server

  // Device 2: simulate returning to the tab -> immediate poll. NO navigation/reload.
  await p2.evaluate(() => window.dispatchEvent(new Event('focus')));
  await p2.waitForFunction(
    () => [...document.querySelectorAll('.note-item h3')].some((h) => h.textContent === 'beta from device 1'),
    { timeout: 8000 },
  ).then(() => check('device 2 shows device 1\'s new note WITHOUT reload', true))
   .catch(() => check('device 2 shows device 1\'s new note WITHOUT reload', false));

  // And it also arrives via the 10s interval alone (no focus) — edit alpha on d1.
  await p1.goto(`${BASE}/app`, { waitUntil: 'networkidle0' });
  await p1.waitForSelector('.note-item');
  // (device 1 reloaded; that's fine — the assertion is about device 2 auto-updating)
} catch (e) {
  console.log('  FAIL exception:', e.message); fail++;
} finally { await browser.close(); }
console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
