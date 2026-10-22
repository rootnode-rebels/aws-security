/**
 * AWSSecurity AI - Client-Side Service Worker
 * Provides offline caching, zero-latency asset serving, background health pings,
 * and Desktop Push Notification handling for critical security alerts.
 */

const CACHE_NAME = 'aws-security-v2.1.0';
const STATIC_ASSETS = [
  '/',
  '/static/css/style.css',
  '/static/js/app.js',
  '/static/js/bg_animation.js',
  '/static/js/fingerprint.js',
  '/static/js/legal_views.js',
  '/static/js/user_portal.js',
  '/static/js/attack_simulator.js',
  '/static/js/soc_dashboard.js',
  '/static/js/cloudwatch_view.js',
  '/static/js/cms_dashboard.js',
  '/static/favicon.png',
  '/static/favicon.ico'
];

// Install: Cache critical static assets
self.addEventListener('install', (event) => {
  self.skipWaiting();
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => {
      console.log('[ServiceWorker] Pre-caching static assets');
      return cache.addAll(STATIC_ASSETS).catch((err) => {
        console.warn('[ServiceWorker] Some assets skipped during pre-cache:', err);
      });
    })
  );
});

// Activate: Clean up older cache versions
self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) => {
      return Promise.all(
        keys.map((key) => {
          if (key !== CACHE_NAME) {
            console.log('[ServiceWorker] Removing obsolete cache:', key);
            return caches.delete(key);
          }
        })
      );
    }).then(() => self.clients.claim())
  );
});

// Fetch: Network-first for APIs, Stale-while-revalidate for static assets
self.addEventListener('fetch', (event) => {
  const url = new URL(event.request.url);

  // 1. API Requests & Event Streams: ALWAYS Network-First, NEVER serve stale data
  if (url.pathname.startsWith('/api/') || url.pathname.includes('/stream')) {
    event.respondWith(
      fetch(event.request).catch((err) => {
        // Return structured offline fallback if network is completely severed
        if (event.request.headers.get('accept')?.includes('application/json')) {
          return new Response(
            JSON.stringify({
              status: 'OFFLINE_MODE',
              message: 'Network offline. Client Service Worker active; retrying automatically.',
              offline: true
            }),
            {
              status: 503,
              headers: { 'Content-Type': 'application/json' }
            }
          );
        }
        throw err;
      })
    );
    return;
  }

  // 2. Static Assets: Stale-While-Revalidate for blazing speed + offline resilience
  event.respondWith(
    caches.match(event.request).then((cachedResponse) => {
      const fetchPromise = fetch(event.request)
        .then((networkResponse) => {
          if (networkResponse && networkResponse.status === 200) {
            const responseToCache = networkResponse.clone();
            caches.open(CACHE_NAME).then((cache) => {
              cache.put(event.request, responseToCache);
            });
          }
          return networkResponse;
        })
        .catch(() => cachedResponse);

      return cachedResponse || fetchPromise;
    })
  );
});

// Background Sync / Periodic Check (when supported by browser)
self.addEventListener('periodicsync', (event) => {
  if (event.tag === 'hourly-health-audit') {
    event.waitUntil(
      fetch('/api/system/status')
        .then((res) => res.json())
        .then((data) => {
          console.log('[ServiceWorker] Periodic health audit completed:', data.status);
        })
        .catch((err) => {
          console.warn('[ServiceWorker] Periodic audit network dropped:', err);
        })
    );
  }
});

// Message Listener from Tabs
self.addEventListener('message', (event) => {
  if (event.data && event.data.type === 'PING_HEALTH') {
    fetch('/api/system/db-health')
      .then((res) => res.json())
      .then((data) => {
        if (event.source) {
          event.source.postMessage({ type: 'HEALTH_PONG', data: data });
        }
      })
      .catch((err) => {
        if (event.source) {
          event.source.postMessage({ type: 'HEALTH_PONG', error: err.message });
        }
      });
  }
});

// Desktop Push Notifications for Real-Time Threat Alerts
self.addEventListener('push', (event) => {
  let payload = { title: 'AWSSecurity Alert', body: 'A security event requires your attention.' };
  try {
    if (event.data) {
      payload = event.data.json();
    }
  } catch (e) {
    if (event.data) {
      payload.body = event.data.text();
    }
  }

  const options = {
    body: payload.body || 'High-risk security anomaly blocked.',
    icon: '/static/favicon.png',
    badge: '/static/favicon.png',
    vibrate: [200, 100, 200],
    data: payload.data || { url: '/' }
  };

  event.waitUntil(self.registration.showNotification(payload.title || '🚨 [AWSSecurity Alert]', options));
});

self.addEventListener('notificationclick', (event) => {
  event.notification.close();
  const rawUrl = (event.notification.data && event.notification.data.url) || '/';
  // Ensure targetUrl is strictly a safe relative path within the current origin
  let targetUrl = '/';
  if (typeof rawUrl === 'string' && rawUrl.startsWith('/') && !rawUrl.startsWith('//') && !rawUrl.includes('\\')) {
    targetUrl = rawUrl;
  }
  event.waitUntil(
    clients.matchAll({ type: 'window', includeUncontrolled: true }).then((clientList) => {
      for (const client of clientList) {
        if (client.url.includes(targetUrl) && 'focus' in client) {
          return client.focus();
        }
      }
      if (clients.openWindow) {
        return clients.openWindow(targetUrl);
      }
    })
  );
});
