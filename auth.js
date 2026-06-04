const CONFIG = {
  // SECURITY: client_id is intentionally public — PKCE public clients have no client_secret.
  // Risk: lookalike phishing apps. Mitigation: ensure redirect URI is strictly pinned to
  // https://munsei-deriv.github.io/dtrader/callback.html in Deriv's OAuth app settings.
  clientId: '33rRsRXIjZYPXgiQ5s1Va',
  redirectUri: window.location.origin + window.location.pathname.replace(/[^/]*$/, '') + 'callback.html',
  authEndpoint: 'https://auth.deriv.com/oauth2/auth',
  tokenEndpoint: 'https://auth.deriv.com/oauth2/token',
  // SECURITY: scope narrowed to 'trade' only — account_manage removed (unnecessary privilege).
  scope: 'trade',
};

// SECURITY: access token lives in memory only after the initial callback→dashboard handoff.
// sessionStorage is used solely as a short-lived transport between those two pages and is
// cleared immediately on first read. This limits XSS exposure to the brief redirect window.
let _memSession = null;

async function generatePKCE() {
  const array = crypto.getRandomValues(new Uint8Array(64));
  const codeVerifier = Array.from(array)
    .map(v => 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~'[v % 66])
    .join('');

  const hash = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(codeVerifier));
  const codeChallenge = btoa(String.fromCharCode(...new Uint8Array(hash)))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

  const state = crypto.getRandomValues(new Uint8Array(16))
    .reduce((s, b) => s + b.toString(16).padStart(2, '0'), '');

  sessionStorage.setItem('pkce_code_verifier', codeVerifier);
  sessionStorage.setItem('oauth_state', state);

  return { codeChallenge, state };
}

async function redirectToAuth({ signup = false } = {}) {
  const { codeChallenge, state } = await generatePKCE();

  const params = new URLSearchParams({
    response_type: 'code',
    client_id: CONFIG.clientId,
    redirect_uri: CONFIG.redirectUri,
    scope: CONFIG.scope,
    state,
    code_challenge: codeChallenge,
    code_challenge_method: 'S256',
  });

  if (signup) params.set('prompt', 'registration');

  window.location.href = `${CONFIG.authEndpoint}?${params}`;
}

async function handleCallback() {
  const params = new URLSearchParams(window.location.search);

  if (params.has('error')) {
    throw new Error(params.get('error_description') || params.get('error'));
  }

  const code = params.get('code');
  const returnedState = params.get('state');
  const storedState = sessionStorage.getItem('oauth_state');
  const codeVerifier = sessionStorage.getItem('pkce_code_verifier');

  if (!code) throw new Error('No authorization code in callback URL.');
  if (returnedState !== storedState) throw new Error('State mismatch — possible CSRF attack.');

  sessionStorage.removeItem('oauth_state');
  sessionStorage.removeItem('pkce_code_verifier');

  // SECURITY: token exchange done browser-side (PKCE public client).
  // For production, proxy this through a backend to avoid CORS and hide exchange details.
  let response;
  try {
    response = await fetch(CONFIG.tokenEndpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        client_id: CONFIG.clientId,
        code,
        code_verifier: codeVerifier,
        redirect_uri: CONFIG.redirectUri,
      }),
    });
  } catch (e) {
    throw new Error(
      'CORS_BLOCKED: The token exchange was blocked by the browser. ' +
      'A backend proxy is required. See: https://github.com/munsei-deriv/dtrader#cors-setup'
    );
  }

  if (!response.ok) {
    const err = await response.json().catch(() => ({}));
    throw new Error(err.error_description || `Token exchange failed: ${response.status}`);
  }

  const token = await response.json();
  _storeSession({ accessToken: token.access_token, expiresIn: token.expires_in });
  return token;
}

// SECURITY: api-core.deriv.com and api.derivws.com are Deriv's documented public API endpoints.
// OTP endpoint follows Deriv's official authentication flow for WebSocket connections.
const REST_BASE = 'https://api.derivws.com';

function derivHeaders(token) {
  return {
    'Authorization': `Bearer ${token}`,
    'Deriv-App-ID': CONFIG.clientId,
  };
}

async function fetchDerivAccount(token) {
  const res = await fetch(`${REST_BASE}/trading/v1/options/accounts`, {
    headers: derivHeaders(token),
  });
  if (!res.ok) throw new Error(`Deriv API error: ${res.status}`);
  return res.json();
}

async function fetchDerivOTP(token, accountId) {
  const url = `${REST_BASE}/trading/v1/options/accounts/${accountId}/otp`;
  console.log('[OTP] POST', url);

  const res = await fetch(url, {
    method: 'POST',
    headers: derivHeaders(token),
  });

  const body = await res.json().catch(() => null);
  console.log('[OTP] status:', res.status, 'body:', JSON.stringify(body));

  if (!res.ok) {
    throw new Error(body?.message ?? body?.error ?? `OTP request failed: ${res.status}`);
  }

  const d = body?.data;
  const otp =
    (typeof d === 'string'         ? d        : null) ??
    (typeof d?.url === 'string'    ? d.url    : null) ??
    (typeof d?.otp === 'string'    ? d.otp    : null) ??
    (typeof d?.ws_url === 'string' ? d.ws_url : null) ??
    (typeof body?.otp === 'string' ? body.otp : null) ??
    (typeof body?.url === 'string' ? body.url : null);

  if (!otp) throw new Error('Cannot parse OTP from response: ' + JSON.stringify(body));

  console.log('[OTP] parsed value:', otp);
  return otp;
}

async function loginDemo() {
  sessionStorage.setItem('prefer_demo', '1');
  await redirectToAuth({ signup: false });
}

function _storeSession({ accessToken, expiresIn }) {
  // Write to sessionStorage only as a one-time handoff to the next page.
  // getSession() clears it from sessionStorage and moves it to memory on first read.
  sessionStorage.setItem('_hs', JSON.stringify({
    t: accessToken,
    e: Date.now() + expiresIn * 1000,
  }));
}

function getSession() {
  // Return from memory if already loaded
  if (_memSession && Date.now() < _memSession.expiresAt) {
    return { token: _memSession.token, demo: _memSession.demo };
  }

  // First call after redirect: migrate from sessionStorage into memory, then clear
  const raw = sessionStorage.getItem('_hs');
  if (raw) {
    try {
      const s = JSON.parse(raw);
      if (Date.now() < s.e) {
        _memSession = { token: s.t, expiresAt: s.e, demo: false };
        sessionStorage.removeItem('_hs'); // cleared immediately — not left sitting in storage
        return { token: _memSession.token, demo: _memSession.demo };
      }
    } catch (_) {}
    sessionStorage.removeItem('_hs');
  }

  return null;
}

function requireAuth() {
  if (!getSession()) window.location.href = 'index.html';
}

function logout() {
  _memSession = null;
  sessionStorage.clear();
  window.location.href = 'index.html';
}
