const CONFIG = {
  clientId: '33rRsRXIjZYPXgiQ5s1Va',
  // Change this to your hosted callback URL and register it with Deriv to enable real OAuth
  redirectUri: window.location.origin + window.location.pathname.replace(/[^/]*$/, '') + 'callback.html',
  authEndpoint: 'https://auth.deriv.com/oauth2/auth',
  tokenEndpoint: 'https://auth.deriv.com/oauth2/token',
  scope: 'trade account_manage',
};

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
    // CORS or network failure — token endpoint blocked direct browser access
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
  _storeSession({ accessToken: token.access_token, expiresIn: token.expires_in, demo: false });
  return token;
}

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

  const otp = body?.data?.otp ?? body?.otp ?? body?.data ?? body;
  console.log('[OTP] parsed otp:', otp);
  return otp;
}

async function loginDemo() {
  // Go through real OAuth so the WebSocket can authenticate — default to demo account after login
  sessionStorage.setItem('prefer_demo', '1');
  await redirectToAuth({ signup: false });
}

function _storeSession({ accessToken, expiresIn, demo }) {
  sessionStorage.setItem('access_token', accessToken);
  sessionStorage.setItem('token_expires_at', Date.now() + expiresIn * 1000);
  sessionStorage.setItem('demo_mode', demo ? '1' : '0');
}

function getSession() {
  const token = sessionStorage.getItem('access_token');
  const expiresAt = Number(sessionStorage.getItem('token_expires_at'));
  if (!token || Date.now() >= expiresAt) return null;
  return { token, demo: sessionStorage.getItem('demo_mode') === '1' };
}

function requireAuth() {
  if (!getSession()) window.location.href = 'index.html';
}

function logout() {
  sessionStorage.clear();
  window.location.href = 'index.html';
}
