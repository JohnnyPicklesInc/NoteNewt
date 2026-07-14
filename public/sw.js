/**
 * Note Newt service worker. Network-first for same-origin assets so code updates
 * always land when online; the cache is an offline fallback only. API calls are
 * never cached (they carry auth + ciphertext). This precaches the app shell so
 * the editor still opens offline.
 */
const CACHE = 'notenewt-v3';
const SHELL = [
  '/app.html',
  '/style.css',
  '/app.js',
  '/notes.js',
  '/db.js',
  '/crypto.js',
  '/sync.js',
  '/passkey.js',
  '/manifest.webmanifest',
  '/favicon.svg',
];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE).then((cache) => Promise.all(SHELL.map((url) => cache.add(url).catch(() => {})))),
  );
  self.skipWaiting();
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) => Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k)))),
  );
  self.clients.claim();
});

self.addEventListener('fetch', (event) => {
  const { request } = event;
  if (request.method !== 'GET') return;

  const url = new URL(request.url);
  if (url.origin !== location.origin) return; // let cross-origin (e.g. ad images) pass through
  if (url.pathname.startsWith('/api/')) return; // never cache API responses

  // Network-first: always prefer fresh code; fall back to cache only when offline.
  event.respondWith(
    fetch(request)
      .then((res) => {
        if (res.ok && res.type === 'basic') {
          const copy = res.clone();
          caches.open(CACHE).then((c) => c.put(request, copy));
        }
        return res;
      })
      .catch(() => caches.match(request).then((cached) => cached || caches.match('/app.html'))),
  );
});
