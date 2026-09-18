'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const { renderPairPage } = require('./mobile-pair-page');
const { createRelayServer } = require('./mobile-connect-relay');

// Minimal desktop-connector handshake (pairing + session exchange require the
// connector to be online; mirrors pairAndConnect in mobile-connect-relay.test.js).
// Node >= 22 exposes a global WebSocket client.
const WebSocket = globalThis.WebSocket;

function waitForOpen(socket) {
  return new Promise((resolve, reject) => {
    const onOpen = () => resolve();
    const onError = (event) => reject(event.error || new Error('WS failed'));
    socket.addEventListener('open', onOpen, { once: true });
    socket.addEventListener('error', onError, { once: true });
  });
}

async function connectDesktop(relay, wsUrl) {
  const desktop = new WebSocket(`${wsUrl}/v1/relay/desktop`, [
    'freebuff-relay-v1',
    'auth-connector-secret',
  ]);
  await waitForOpen(desktop);
  desktop.send(JSON.stringify({ type: 'connector.register', connectorId: 'desktop-test' }));
  await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('no connector.ready')), 2000);
    desktop.addEventListener('message', (event) => {
      const message = JSON.parse(event.data);
      if (message.type === 'connector.ready') { clearTimeout(timer); resolve(); }
    }, { once: false });
  });
  return desktop;
}

// --- unit: page rendering ---------------------------------------------------

test('pair page contains the client flow and hardening headers contract', () => {
  const html = renderPairPage();
  // The three-step flow the APK performs natively, now in page JS.
  assert.match(html, /\/v1\/pairings\/claim/);
  assert.match(html, /\/v1\/mobile\/session/);
  assert.match(html, /location\.replace\('\/'\)/);
  // Token comes from the URL fragment and is wiped from history afterwards.
  assert.match(html, /location\.hash/);
  assert.match(html, /history\.replaceState/);
  // Device key: short random string (validateDeviceKey accepts any short value).
  assert.match(html, /devicePublicKey/);
  // The page must never leak the pairing token into any server-visible URL.
  assert.doesNotMatch(html, /src=|href=/);
});

// --- integration: live relay ---------------------------------------------------

async function startRelay() {
  const server = createRelayServer({
    stateFile: null,
    connectorToken: 'connector-secret',
    adminToken: 'admin-secret',
    publicHttpUrl: 'http://127.0.0.1',
    publicWsUrl: 'ws://127.0.0.1',
    appUrl: 'http://127.0.0.1/pair',
    uiUrl: 'http://127.0.0.1',
  });
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  const address = server.address();
  return {
    server,
    hub: server.hub,
    baseUrl: `http://127.0.0.1:${address.port}`,
  };
}

test('relay serves the pairing page at GET /pair', async () => {
  const relay = await startRelay();
  try {
    const res = await fetch(`${relay.baseUrl}/pair`);
    assert.equal(res.status, 200);
    assert.match(res.headers.get('content-type'), /text\/html/);
    assert.equal(res.headers.get('cache-control'), 'no-store');
    assert.match(res.headers.get('content-security-policy'), /frame-ancestors 'none'/);
    const body = await res.text();
    assert.match(body, /Freebuff pairing/);
    assert.match(body, /\/v1\/pairings\/claim/);
  } finally {
    relay.hub.close();
    await new Promise((resolve) => relay.server.close(resolve));
  }
});

test('browser pairing flow: page APIs claim a pairing and exchange it for a session cookie', async () => {
  const relay = await startRelay();
  let desktop;
  try {
    const wsPort = relay.server.address().port;
    desktop = await connectDesktop(relay, `ws://127.0.0.1:${wsPort}`);
    // Desktop connector creates a pairing whose URL points at /pair.
    const started = await fetch(`${relay.baseUrl}/v1/pairings`, {
      method: 'POST',
      headers: { authorization: 'Bearer connector-secret', 'content-type': 'application/json' },
      body: JSON.stringify({
        connectorId: 'desktop-test',
        appUrl: `${relay.baseUrl}/pair`,
        relayUrl: `ws://127.0.0.1:${relay.server.address().port}`,
        uiUrl: relay.baseUrl,
        ttlSeconds: 60,
      }),
    });
    assert.equal(started.status, 201);
    const startedBody = await started.json();
    const pairingUrl = new URL(startedBody.pairingUrl);
    // Sanity: the pairing link lands on the page this feature serves.
    assert.equal(pairingUrl.pathname, '/pair');
    const qr = new URLSearchParams(pairingUrl.hash.slice(1));

    // What the page JS does (same-origin fetches from the browser):
    const claim = await fetch(`${relay.baseUrl}/v1/pairings/claim`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        pairingId: qr.get('pairingId'),
        token: qr.get('token'),
        deviceName: 'Browser test',
        devicePublicKey: 'browser-test-key',
      }),
    });
    assert.equal(claim.status, 200);
    const claimed = await claim.json();

    const session = await fetch(`${relay.baseUrl}/v1/mobile/session`, {
      headers: { authorization: `Bearer ${claimed.accessToken}` },
    });
    assert.equal(session.status, 200);
    const cookie = session.headers.get('set-cookie');
    assert.match(cookie, /HttpOnly/);
    assert.match(cookie, /Secure/);
    assert.match(cookie, /SameSite=Strict/);
    // UI-request proxying with the cookie is covered by mobile-connect-relay.test.js.
  } finally {
    if (desktop) desktop.close();
    relay.hub.close();
    await new Promise((resolve) => relay.server.close(resolve));
  }
});
