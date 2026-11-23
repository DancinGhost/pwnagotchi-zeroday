'use strict';

const CACHE_NAME = 'zeroday-web-v3';
const PRECACHE_URLS = [
  './',
  './index.html',
  './styles.css',
  './manifest.json',
  './icon.svg',
  './js/fp.js',
  './js/themes.js',
  './js/wifi_analysis.js',
  './js/pet_logic.js',
  './js/ui_model.js',
  './js/canvas_gfx.js',
  './js/airwaves_sim.js',
  './js/buzzer_sfx.js',
  './js/app.js'
];

self.addEventListener('install', function (event) {
  event.waitUntil(
    caches.open(CACHE_NAME).then(function (cache) {
      return cache.addAll(PRECACHE_URLS);
    }).then(function () {
      return self.skipWaiting();
    })
  );
});

self.addEventListener('activate', function (event) {
  event.waitUntil(
    caches.keys().then(function (keys) {
      return Promise.all(
        keys.filter(function (k) { return k !== CACHE_NAME; }).map(function (k) {
          return caches.delete(k);
        })
      );
    }).then(function () {
      return self.clients.claim();
    })
  );
});

self.addEventListener('fetch', function (event) {
  if (event.request.method !== 'GET') return;
  const reqUrl = new URL(event.request.url);
  if (reqUrl.origin !== self.location.origin) return;

  if (event.request.mode === 'navigate') {
    event.respondWith(
      fetch(event.request).then(function (netResp) {
        if (netResp && netResp.ok) {
          const clone = netResp.clone();
          caches.open(CACHE_NAME).then(function (cache) { cache.put(event.request, clone); });
        }
        return netResp;
      }).catch(function () {
        return caches.match('./index.html');
      })
    );
    return;
  }

  // Stale-while-revalidate for same-origin static assets
  event.respondWith(
    caches.open(CACHE_NAME).then(function (cache) {
      return cache.match(event.request).then(function (cached) {
        const netPromise = fetch(event.request).then(function (netResp) {
          if (netResp && netResp.ok && netResp.type === 'basic') {
            cache.put(event.request, netResp.clone());
          }
          return netResp;
        }).catch(function () {
          return cached;
        });
        return cached || netPromise;
      });
    })
  );
});
