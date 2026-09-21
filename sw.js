/**
 * sw.js — Service Worker do Painel de Formulários (Cadastro Imobiliário)
 * ------------------------------------------------------------------
 * Escopo: apenas as páginas do formulário mobile.
 *   index.html            → roteamento (decide login x formulário)
 *   formulario-login.html → autenticação
 *   formulario.html       → ficha de cadastro
 *
 * Estratégia:
 *   - App shell (HTML/manifest/ícones/logo) fica em cache, permitindo
 *     abrir o app offline ou com conexão instável.
 *   - Navegações (HTML) usam "network-first": tenta a rede primeiro
 *     (para sempre pegar a versão mais nova) e cai para o cache
 *     apenas se a rede falhar.
 *   - Assets estáticos do próprio app (ícones, manifest, logo) usam
 *     "cache-first" com atualização em segundo plano.
 *   - Tudo que for de outra origem (Firebase Auth, Firestore, APIs
 *     do Google, o Worker de gravação em /fichas etc.) NÃO é
 *     interceptado — passa direto para a rede, sem cache. Isso evita
 *     qualquer interferência em login, sessão ou envio de fichas.
 * ------------------------------------------------------------------
 */

const CACHE_NAME = 'cadmob-form-v1';

const APP_SHELL = [
  './index.html',
  './formulario.html',
  './formulario-login.html',
  './manifest.json',
  './logo.png',
  './icons/icon-192.png',
  './icons/icon-512.png',
  './icons/icon-maskable-192.png',
  './icons/icon-maskable-512.png',
  './icons/apple-touch-icon.png'
];

// ============================================================
// INSTALL — pré-carrega o app shell
// ============================================================
self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then((cache) => cache.addAll(APP_SHELL))
      .then(() => self.skipWaiting())
  );
});

// ============================================================
// ACTIVATE — remove caches de versões antigas
// ============================================================
self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys()
      .then((keys) => Promise.all(
        keys
          .filter((key) => key !== CACHE_NAME)
          .map((key) => caches.delete(key))
      ))
      .then(() => self.clients.claim())
  );
});

// ============================================================
// FETCH
// ============================================================
self.addEventListener('fetch', (event) => {
  const { request } = event;

  // Só GET, e só mesma origem — qualquer outra coisa (Firebase,
  // Firestore, o Worker de /fichas, fontes externas etc.) segue
  // direto para a rede, sem passar pelo Service Worker.
  if (request.method !== 'GET') return;
  if (new URL(request.url).origin !== self.location.origin) return;

  // Navegações (carregar uma página HTML): network-first.
  if (request.mode === 'navigate') {
    event.respondWith(
      fetch(request)
        .then((response) => {
          const copy = response.clone();
          caches.open(CACHE_NAME).then((cache) => cache.put(request, copy));
          return response;
        })
        .catch(() => caches.match(request).then((cached) => cached || caches.match('./index.html')))
    );
    return;
  }

  // Demais requisições same-origin conhecidas do app shell (ícones,
  // manifest, logo, css/js referenciados no futuro): cache-first,
  // com atualização em segundo plano.
  event.respondWith(
    caches.match(request).then((cached) => {
      const network = fetch(request)
        .then((response) => {
          const copy = response.clone();
          caches.open(CACHE_NAME).then((cache) => cache.put(request, copy));
          return response;
        })
        .catch(() => cached);
      return cached || network;
    })
  );
});
