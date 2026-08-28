// TERO HQ — Admin PWA Service Worker
// Scope: /tero-hq/
// Separate from the user-app SW (/sw.js, scope /) so both PWAs install
// and operate independently. This SW ONLY handles /tero-hq/* requests.

self.addEventListener('install', () => {
  self.skipWaiting();
});

self.addEventListener('activate', (event) => {
  event.waitUntil(self.clients.claim());
});

self.addEventListener('push', (event) => {
  const data = event.data?.json() ?? {};
  event.waitUntil(
    self.registration.showNotification(data.title ?? 'TERO HQ', {
      body: data.body ?? '',
      icon: data.icon ?? '/icon-192.png',
      badge: '/icon-192.png',
      data: { url: data.url ?? '/tero-hq/dashboard' },
    })
  );
});

self.addEventListener('notificationclick', (event) => {
  event.notification.close();
  const url = event.notification.data?.url ?? '/tero-hq/dashboard';
  event.waitUntil(self.clients.openWindow(url));
});
