// ── Cache version — bump this string whenever badge images are replaced ──────
const BADGE_CACHE = "tero-badges-v1";

const BADGE_URLS = [
  "/badges/badge0.png",
  "/badges/badge1.png",
  "/badges/badge2.png",
  "/badges/badge3.png",
  "/badges/badge4.png",
  "/badges/badge5.png",
  "/badges/badge6.png",
  "/badges/badge7.png",
];

// ── Install: precache all badges before the SW activates ─────────────────────
self.addEventListener("install", (event) => {
  event.waitUntil(
    caches
      .open(BADGE_CACHE)
      .then((cache) => cache.addAll(BADGE_URLS))
      .then(() => self.skipWaiting())
  );
});

// ── Activate: remove any old badge caches from previous versions ──────────────
self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches
      .keys()
      .then((keys) =>
        Promise.all(
          keys
            .filter((k) => k.startsWith("tero-badges-") && k !== BADGE_CACHE)
            .map((k) => caches.delete(k))
        )
      )
      .then(() => self.clients.claim())
  );
});

// ── Fetch: Cache-First for badge images, Stale-While-Revalidate update ────────
self.addEventListener("fetch", (event) => {
  const url = new URL(event.request.url);

  if (url.pathname.startsWith("/badges/") && url.pathname.endsWith(".png")) {
    event.respondWith(
      caches.open(BADGE_CACHE).then(async (cache) => {
        const cached = await cache.match(event.request);
        if (cached) {
          // Serve from cache immediately; refresh in background (stale-while-revalidate)
          event.waitUntil(
            fetch(event.request)
              .then((fresh) => {
                if (fresh.ok) cache.put(event.request, fresh.clone());
              })
              .catch(() => {})
          );
          return cached;
        }
        // Not in cache yet — fetch, store, then return
        const fresh = await fetch(event.request);
        if (fresh.ok) cache.put(event.request, fresh.clone());
        return fresh;
      })
    );
    return;
  }
});

// ── Push notifications ────────────────────────────────────────────────────────
self.addEventListener("push", (event) => {
  const data = event.data?.json() ?? {};
  event.waitUntil(
    self.registration.showNotification(data.title ?? "Notification", {
      body: data.body ?? "",
      icon: data.icon ?? "/icon-192.png",
      badge: "/icon-192.png",
      data: { url: data.url ?? "/" },
    })
  );
});

self.addEventListener("notificationclick", (event) => {
  event.notification.close();
  const url = event.notification.data?.url ?? "/";
  event.waitUntil(clients.openWindow(url));
});
