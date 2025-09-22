const CACHE_NAME = 'port-forwarder-v1.0.0';
const STATIC_CACHE_NAME = 'static-v1.0.0';
const DYNAMIC_CACHE_NAME = 'dynamic-v1.0.0';

// Files to cache for offline functionality
const STATIC_ASSETS = [
  '/',
  '/login.html',
  '/manifest.json',
  'https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css',
  'https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css',
  'https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js',
  'https://rsms.me/inter/inter.css'
];

// Install event - cache static assets
self.addEventListener('install', (event) => {
  console.log('[Service Worker] Installing...');

  event.waitUntil(
    caches.open(STATIC_CACHE_NAME)
      .then((cache) => {
        console.log('[Service Worker] Pre-caching static assets');
        return cache.addAll(STATIC_ASSETS);
      })
      .then(() => {
        console.log('[Service Worker] Static assets cached successfully');
        return self.skipWaiting();
      })
      .catch((error) => {
        console.error('[Service Worker] Failed to cache static assets:', error);
      })
  );
});

// Activate event - clean up old caches
self.addEventListener('activate', (event) => {
  console.log('[Service Worker] Activating...');

  const currentCaches = [STATIC_CACHE_NAME, DYNAMIC_CACHE_NAME];

  event.waitUntil(
    caches.keys()
      .then((cacheNames) => {
        return Promise.all(
          cacheNames.map((cacheName) => {
            if (!currentCaches.includes(cacheName)) {
              console.log('[Service Worker] Deleting old cache:', cacheName);
              return caches.delete(cacheName);
            }
          })
        );
      })
      .then(() => {
        console.log('[Service Worker] Activated and ready');
        return self.clients.claim();
      })
  );
});

// Fetch event - serve from cache or network
self.addEventListener('fetch', (event) => {
  const { request } = event;
  const url = new URL(request.url);

  // Skip cross-origin requests and non-GET requests
  if (url.origin !== location.origin || request.method !== 'GET') {
    return;
  }

  // Skip auth-related requests - let them go directly to server
  if (url.pathname === '/' || url.pathname === '/login' || url.pathname.startsWith('/api/')) {
    // Let the browser handle these directly for proper redirect handling
    return;
  }

  // Handle static assets only
  event.respondWith(handleStaticRequest(request));
});

// Handle API requests with network-first strategy (for non-auth APIs only)
async function handleApiRequest(request) {
  const url = new URL(request.url);

  try {
    // Always try network first for API requests
    const networkResponse = await fetch(request);

    // Cache successful responses for some API endpoints
    if (networkResponse.ok && shouldCacheApiResponse(url.pathname)) {
      const cache = await caches.open(DYNAMIC_CACHE_NAME);
      cache.put(request, networkResponse.clone());
    }

    return networkResponse;
  } catch (error) {
    console.log('[Service Worker] Network failed for API request:', request.url);

    // Try to serve from cache for certain API endpoints
    if (shouldServeApiFromCache(url.pathname)) {
      const cachedResponse = await caches.match(request);
      if (cachedResponse) {
        console.log('[Service Worker] Serving API from cache:', request.url);
        return cachedResponse;
      }
    }

    // Return offline response for critical API endpoints
    return createOfflineApiResponse(url.pathname);
  }
}

// Handle static assets with cache-first strategy
async function handleStaticRequest(request) {
  try {
    // Try cache first
    const cachedResponse = await caches.match(request);
    if (cachedResponse) {
      console.log('[Service Worker] Serving from cache:', request.url);
      return cachedResponse;
    }

    // If not in cache, try network
    const networkResponse = await fetch(request);

    // Cache the response for future use
    if (networkResponse.ok) {
      const cache = await caches.open(DYNAMIC_CACHE_NAME);
      cache.put(request, networkResponse.clone());
    }

    return networkResponse;
  } catch (error) {
    console.log('[Service Worker] Network failed for static request:', request.url);

    // For HTML requests, return offline page
    if (request.headers.get('accept').includes('text/html')) {
      return createOfflineHtmlResponse();
    }

    // For other requests, return empty response
    return new Response('', { status: 408, statusText: 'Request Timeout' });
  }
}

// Determine which API responses should be cached
function shouldCacheApiResponse(pathname) {
  const cacheableEndpoints = [
    '/api/config',
    '/api/ip'
  ];

  return cacheableEndpoints.some(endpoint => pathname.startsWith(endpoint));
}

// Determine which API requests can be served from cache when offline
function shouldServeApiFromCache(pathname) {
  const offlineServeableEndpoints = [
    '/api/config',
    '/api/ip'
  ];

  return offlineServeableEndpoints.some(endpoint => pathname.startsWith(endpoint));
}

// Create offline API response
function createOfflineApiResponse(pathname) {
  const offlineResponses = {
    '/api/config': {
      admin_addr: 'offline',
      forwards: []
    },
    '/api/ip': {
      ip: 'offline'
    },
    '/api/ip-pool': {
      currentSize: 0,
      maxSize: 10,
      ips: []
    }
  };

  const defaultResponse = { error: 'Offline', message: 'This feature requires an internet connection' };

  for (const [endpoint, response] of Object.entries(offlineResponses)) {
    if (pathname.startsWith(endpoint)) {
      return new Response(JSON.stringify(response), {
        status: 200,
        headers: { 'Content-Type': 'application/json' }
      });
    }
  }

  return new Response(JSON.stringify(defaultResponse), {
    status: 503,
    headers: { 'Content-Type': 'application/json' }
  });
}

// Create offline HTML response
function createOfflineHtmlResponse() {
  const offlineHtml = `
    <!DOCTYPE html>
    <html lang="en" data-bs-theme="light">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Port Forwarder - Offline</title>
        <style>
            body {
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
                background: linear-gradient(135deg, #f8f9fa 0%, rgba(13, 110, 253, 0.05) 100%);
                min-height: 100vh;
                display: flex;
                align-items: center;
                justify-content: center;
                margin: 0;
                padding: 1rem;
            }
            .offline-container {
                text-align: center;
                background: rgba(255, 255, 255, 0.9);
                backdrop-filter: blur(10px);
                border-radius: 16px;
                padding: 2rem;
                box-shadow: 0 8px 32px rgba(0, 0, 0, 0.1);
                max-width: 400px;
            }
            .offline-icon {
                font-size: 4rem;
                margin-bottom: 1rem;
                color: #dc3545;
            }
            .btn {
                background: #0d6efd;
                color: white;
                border: none;
                padding: 0.75rem 1.5rem;
                border-radius: 8px;
                text-decoration: none;
                display: inline-block;
                margin-top: 1rem;
                transition: background 0.3s ease;
            }
            .btn:hover {
                background: #0b5ed7;
            }
        </style>
    </head>
    <body>
        <div class="offline-container">
            <div class="offline-icon">📡</div>
            <h1>You're Offline</h1>
            <p>Port Forwarder requires an internet connection to manage your configuration.</p>
            <p>Please check your connection and try again.</p>
            <button class="btn" onclick="window.location.reload()">Try Again</button>
        </div>
    </body>
    </html>
  `;

  return new Response(offlineHtml, {
    status: 200,
    headers: { 'Content-Type': 'text/html' }
  });
}

// Handle background sync for form submissions
self.addEventListener('sync', (event) => {
  if (event.tag === 'config-sync') {
    event.waitUntil(syncConfig());
  }
});

// Sync configuration when back online
async function syncConfig() {
  try {
    const cache = await caches.open(DYNAMIC_CACHE_NAME);
    const pendingRequest = await cache.match('/api/config-pending');

    if (pendingRequest) {
      const pendingData = await pendingRequest.json();

      // Attempt to sync with server
      const response = await fetch('/api/config', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(pendingData)
      });

      if (response.ok) {
        // Remove pending data after successful sync
        await cache.delete('/api/config-pending');
        console.log('[Service Worker] Configuration synced successfully');
      }
    }
  } catch (error) {
    console.error('[Service Worker] Failed to sync configuration:', error);
  }
}

// Listen for messages from the main thread
self.addEventListener('message', (event) => {
  if (event.data && event.data.type === 'SKIP_WAITING') {
    self.skipWaiting();
  }

  if (event.data && event.data.type === 'CACHE_CONFIG') {
    // Store configuration data for offline access
    caches.open(DYNAMIC_CACHE_NAME).then((cache) => {
      cache.put('/api/config-pending', new Response(JSON.stringify(event.data.config)));
    });
  }
});

console.log('[Service Worker] Service Worker script loaded');