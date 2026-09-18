'use strict';

/**
 * Browser pairing page served by the relay at GET /pair.
 *
 * The Android APK performs pairing natively: parse the pairing URL, POST
 * /v1/pairings/claim, exchange the access token for a Secure/HttpOnly
 * session cookie via GET /v1/mobile/session, then load the UI. This page
 * performs the same three steps from plain JavaScript so a phone (or any)
 * browser can pair without the app. No Freebuff APK required.
 *
 * Flow: URL hash (#pairingId=..&token=..) -> POST /v1/pairings/claim
 *       -> GET /v1/mobile/session (Bearer) -> session cookie is set by the
 *       relay -> redirect to "/" where the proxy serves the Freebuff UI with
 *       the injected mobile layer.
 *
 * The token lives only in the URL fragment (never sent to a server by the
 * browser) and in page memory; it is never stored. The hash is cleared after
 * the claim so the token does not linger in history state.
 */

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (ch) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  }[ch]));
}

function pageJs() {
  return `
(function () {
  'use strict';
  var statusEl = document.getElementById('status');
  function show(kind, text) {
    statusEl.className = kind;
    statusEl.textContent = text;
  }
  function randomId() {
    var bytes = new Uint8Array(32);
    crypto.getRandomValues(bytes);
    var bin = '';
    for (var i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return btoa(bin).replace(/\\+/g, '-').replace(/\\//g, '_').replace(/=+$/, '');
  }
  async function pair() {
    var params = new URLSearchParams(location.hash.replace(/^#/, ''));
    var pairingId = params.get('pairingId');
    var token = params.get('token');
    if (!pairingId || !token) {
      show('err', 'Missing pairing credentials. Open the full pairing link (it must contain #pairingId=... and token=...).');
      return;
    }
    history.replaceState(null, '', location.pathname);
    show('info', 'Claiming pairing request...');
    var claimRes;
    try {
      claimRes = await fetch('/v1/pairings/claim', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          pairingId: pairingId,
          token: token,
          deviceName: 'Browser ' + (navigator.platform || ''),
          devicePublicKey: randomId(),
        }),
      });
    } catch (e) {
      show('err', 'Cannot reach the relay. Check the network and try the link again.');
      return;
    }
    if (!claimRes.ok) {
      var detail = '';
      try { detail = (await claimRes.json()).error || ''; } catch (e) { /* ignore */ }
      show('err', 'Pairing failed (' + claimRes.status + (detail ? ' ' + detail : '') + '). The link may be expired or already used. Request a new pairing link.');
      return;
    }
    var claimed;
    try { claimed = await claimRes.json(); } catch (e) {
      show('err', 'Relay returned an unexpected pairing response.');
      return;
    }
    show('info', 'Establishing session...');
    var sessionRes;
    try {
      sessionRes = await fetch('/v1/mobile/session', {
        headers: { Authorization: 'Bearer ' + claimed.accessToken },
      });
    } catch (e) {
      show('err', 'Cannot establish a session with the relay.');
      return;
    }
    if (!sessionRes.ok) {
      show('err', 'Session establishment failed (' + sessionRes.status + '). Request a new pairing link.');
      return;
    }
    show('ok', 'Paired. Opening Freebuff...');
    location.replace('/');
  }
  pair();
})();
`;
}

/** Renders the self-contained /pair HTML page (no external assets). */
function renderPairPage() {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="color-scheme" content="dark">
<title>Freebuff — Pair device</title>
<style>
  :root { color-scheme: dark; }
  * { box-sizing: border-box; }
  body {
    margin: 0; min-height: 100vh; display: flex; align-items: center; justify-content: center;
    background: #0b0b0f; color: #e8e8ee;
    font: 16px/1.5 system-ui, -apple-system, 'Segoe UI', Roboto, sans-serif;
    padding: 24px;
  }
  .card {
    width: 100%; max-width: 380px; padding: 28px 24px; border-radius: 14px;
    background: #14141b; border: 1px solid #26262f; text-align: center;
  }
  h1 { font-size: 18px; margin: 0 0 6px; }
  .sub { font-size: 13px; color: #8a8a98; margin: 0 0 20px; }
  #status { font-size: 14px; border-radius: 8px; padding: 12px 14px; word-break: break-word; }
  #status.info { background: #1b1f2a; color: #aebacf; }
  #status.ok { background: #12291c; color: #7fd7a2; }
  #status.err { background: #2c1618; color: #e58a92; }
  .spinner {
    margin: 0 auto 16px; width: 28px; height: 28px; border-radius: 50%;
    border: 3px solid #2a2a36; border-top-color: #6c8cff;
    animation: spin 0.9s linear infinite;
  }
  @keyframes spin { to { transform: rotate(360deg); } }
  .hide { display: none; }
</style>
</head>
<body>
<div class="card">
  <h1>Freebuff pairing</h1>
  <p class="sub">Complete pairing to connect this browser to your desktop agent.</p>
  <div class="spinner" id="spinner"></div>
  <div id="status" class="info">Starting...</div>
</div>
<script>${pageJs()}<\/script>
</body>
</html>`;
}

/** Relay route body for GET /pair. Sets the same hardening headers as sendJson. */
function servePairPage(res, requestOptions = {}) {
  const body = renderPairPage();
  res.statusCode = 200;
  res.setHeader('cache-control', 'no-store');
  res.setHeader('x-content-type-options', 'nosniff');
  res.setHeader('referrer-policy', 'no-referrer');
  res.setHeader('content-security-policy', "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; frame-ancestors 'none'");
  res.setHeader('content-type', 'text/html; charset=utf-8');
  res.setHeader('content-length', Buffer.byteLength(body));
  if (requestOptions.allowedOrigin && requestOptions.requestOrigin === requestOptions.allowedOrigin) {
    res.setHeader('access-control-allow-origin', requestOptions.allowedOrigin);
    res.setHeader('vary', 'Origin');
  }
  res.end(body);
}

module.exports = { renderPairPage, servePairPage, escapeHtml };
