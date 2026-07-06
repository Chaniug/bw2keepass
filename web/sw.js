// Pass2KDBX Service Worker
// 版本号变更时，旧缓存会被自动清理（activate 事件中处理）
const CACHE_VERSION = 'v5';
const CACHE_NAME = `pass2kdbx-${CACHE_VERSION}`;
const ASSETS = [
  '/',
  '/index.html',
  '/manifest.json',
  'https://cdn.jsdelivr.net/npm/kdbxweb@2.1.1/dist/kdbxweb.min.js',
];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => {
      return cache.addAll(ASSETS);
    })
  );
  self.skipWaiting();
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) => {
      return Promise.all(
        keys.filter((k) => k !== CACHE_NAME).map((k) => caches.delete(k))
      );
    })
  );
  self.clients.claim();
});

self.addEventListener('fetch', (event) => {
  // 网络优先，失败回退缓存（确保用户在线时拿到最新版本）
  event.respondWith(
    fetch(event.request)
      .then((response) => {
        // 只缓存成功的同源响应和 CDN 资源
        if (response.ok && (event.request.url.includes(location.origin) || event.request.url.includes('cdn.jsdelivr'))) {
          const clone = response.clone();
          caches.open(CACHE_NAME).then((cache) => cache.put(event.request, clone));
        }
        return response;
      })
      .catch(() => caches.match(event.request).then((cached) => cached || new Response('离线模式', { status: 503 })))
  );
});
