/**
 * Mailboxer PWA & Web Push Service Worker
 *
 * Provides offline shell caching, background push notifications,
 * system tray icon badging, and deep-link navigation.
 */

const CACHE_NAME = 'mailboxer-shell-v2';
const STATIC_ASSETS = [
  '/',
  '/index.html',
  '/style.css',
  '/app.js',
  '/manifest.json',
  '/icon.svg'
];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => {
      return cache.addAll(STATIC_ASSETS).catch(() => {});
    })
  );
  self.skipWaiting();
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) => {
      return Promise.all(
        keys.filter((key) => key !== CACHE_NAME).map((key) => caches.delete(key))
      );
    }).then(() => self.clients.claim())
  );
});

// Stale-while-revalidate for static shell assets, network-only for /api/
self.addEventListener('fetch', (event) => {
  const url = new URL(event.request.url);

  // Skip caching for non-GET or API endpoints
  if (event.request.method !== 'GET' || url.pathname.startsWith('/api/') || url.pathname.startsWith('/health')) {
    return;
  }

  event.respondWith(
    fetch(event.request)
      .then((networkResponse) => {
        if (networkResponse && networkResponse.status === 200) {
          const responseToCache = networkResponse.clone();
          caches.open(CACHE_NAME).then((cache) => {
            cache.put(event.request, responseToCache);
          });
        }
        return networkResponse;
      })
      .catch(() => {
        return caches.match(event.request).then((cachedResponse) => {
          if (cachedResponse) return cachedResponse;
          if (event.request.mode === 'navigate') {
            return caches.match('/index.html') || caches.match('/');
          }
        });
      })
  );
});

// Background Web Push Notifications
self.addEventListener('push', (event) => {
  let payload = {};
  if (event.data) {
    try {
      payload = event.data.json();
    } catch {
      payload = { title: 'Mailboxer VIP Alert', body: event.data.text() };
    }
  }

  const title = payload.title || '⭐ Mailboxer VIP Alert';
  const options = {
    body: payload.body || 'New high-priority email received.',
    icon: payload.icon || '/icon.svg',
    badge: payload.badge || '/icon.svg',
    tag: payload.tag || `mailboxer-msg-${payload.data?.messageId || Date.now()}`,
    renotify: true,
    data: payload.data || { url: '/' },
    actions: payload.actions || [
      { action: 'open', title: 'Open Mailboxer' },
      { action: 'read', title: 'Mark as Read' }
    ]
  };

  event.waitUntil(self.registration.showNotification(title, options));
});

self.addEventListener('notificationclick', (event) => {
  event.notification.close();

  const action = event.action;
  const data = event.notification.data || {};
  const targetUrl = data.url || '/';

  if (action === 'read' && data.messageId) {
    event.waitUntil(
      fetch(`/api/messages/${encodeURIComponent(data.messageId)}/read`, {
        method: 'POST'
      }).catch(() => {})
    );
    return;
  }

  // Open window or focus existing
  event.waitUntil(
    self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then((windowClients) => {
      for (const client of windowClients) {
        if (client.url && 'focus' in client) {
          // Tell the open app which message to show, then bring it forward
          client.postMessage({ type: 'MAILBOXER_OPEN_URL', url: targetUrl });
          return client.focus();
        }
      }
      if (self.clients.openWindow) {
        return self.clients.openWindow(targetUrl);
      }
    })
  );
});
