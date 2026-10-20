/**
 * Mailboxer Web Push Service Worker
 *
 * Handles background push notifications, system tray icon badging,
 * quick action buttons, and window focus / deep-link navigation.
 */

self.addEventListener('install', (event) => {
  self.skipWaiting();
});

self.addEventListener('activate', (event) => {
  event.waitUntil(self.clients.claim());
});

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
    icon: payload.icon || '/favicon.ico',
    badge: payload.badge || '/favicon.ico',
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
          return client.focus();
        }
      }
      if (self.clients.openWindow) {
        return self.clients.openWindow(targetUrl);
      }
    })
  );
});
