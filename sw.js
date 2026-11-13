'use strict';
/* Lantern — service worker: makes the hosted app installable and usable offline.
   It only ever touches Lantern's own files. Requests to other origins (pivot links, Recon APIs) are not
   intercepted, cached or logged. Strategy: network first so a new deploy shows up at once, cache as the offline fallback.
   Keep SHELL in step with the <script> tags in index.html (tests/run.js checks this). */
const CACHE = 'lantern-shell-v1';
const SHELL = [
  './',
  'index.html',
  'manifest.webmanifest',
  'css/app.css',
  'icons/icon-192.png',
  'js/app.js',
  'js/core.js',
  'js/crypto.js',
  'js/detect.js',
  'js/geo.js',
  'js/metadata.js',
  'js/pivots.js',
  'js/views/analysis.js',
  'js/views/analyze.js',
  'js/views/case.js',
  'js/views/collect.js',
  'js/views/geoview.js',
  'js/views/graph.js',
  'js/views/mail.js',
  'js/views/ops.js',
  'js/views/recon.js',
  'js/views/timeline.js',
  'js/views/toolbox.js',
  'js/views/tools2.js',
];

self.addEventListener('install', (e) => {
  e.waitUntil(caches.open(CACHE).then((c) => c.addAll(SHELL)).then(() => self.skipWaiting()));
});
self.addEventListener('activate', (e) => {
  e.waitUntil(caches.keys().then((keys) => Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k)))).then(() => self.clients.claim()));
});
self.addEventListener('fetch', (e) => {
  const req = e.request;
  if (req.method !== 'GET' || new URL(req.url).origin !== self.location.origin) return;
  e.respondWith(
    fetch(req).then((res) => {
      if (res.ok) { const copy = res.clone(); caches.open(CACHE).then((c) => c.put(req, copy)); }
      return res;
    }).catch(() => caches.match(req, { ignoreSearch: true }).then((hit) => hit || (req.mode === 'navigate' ? caches.match('index.html') : Response.error()))),
  );
});
