// Pass2KDBX Service Worker
// 版本号变更时，旧缓存会被自动清理（activate 事件中处理）
const CACHE_VERSION = 'v7';
const CACHE_NAME = `pass2kdbx-${CACHE_VERSION}`;
const ASSETS = [
  '/',
  '/index.html',
  '/manifest.json',
  'https://cdn.jsdelivr.net/npm/kdbxweb@2.1.1/dist/kdbxweb.min.js',
  'https://cdn.jsdelivr.net/npm/hash-wasm@4.11.0/dist/argon2.umd.min.js',
  'https://cdn.jsdelivr.net/npm/jszip@3.10.1/dist/jszip.min.js',
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
  const url = event.request.url;
  const isNavigation = event.request.mode === 'navigate';
  const isSameOrigin = url.startsWith(location.origin);
  const isHtml = isSameOrigin && (isNavigation || url.endsWith('.html') || url.endsWith('/'));

  // 页面（index.html）与同源 HTML：绕过 HTTP 缓存，始终向服务器取最新版本。
  // 否则 GitHub Pages 的缓存头会让 network-first 实际拿到旧缓存，导致新部署的解密
  // 修复对用户不生效（表现为“密码正确却解不开”）。
  if (isHtml) {
    event.respondWith(
      fetch(event.request, { cache: 'no-cache' })
        .then((response) => {
          if (response.ok) {
            const clone = response.clone();
            caches.open(CACHE_NAME).then((cache) => cache.put(event.request, clone));
          }
          return response;
        })
        .catch(() => caches.match(event.request).then((cached) => cached || new Response('离线模式', { status: 503 })))
    );
    return;
  }

  // 其余资源（含版本固定的 CDN）：网络优先，失败回退缓存
  event.respondWith(
    fetch(event.request)
      .then((response) => {
        if (response.ok && (isSameOrigin || url.includes('cdn.jsdelivr'))) {
          const clone = response.clone();
          caches.open(CACHE_NAME).then((cache) => cache.put(event.request, clone));
        }
        return response;
      })
      .catch(() => caches.match(event.request).then((cached) => cached || new Response('离线模式', { status: 503 })))
  );
});
