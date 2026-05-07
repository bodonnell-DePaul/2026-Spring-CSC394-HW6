import { useEffect, useMemo, useState } from 'react';
import {
  Box,
  ClipboardList,
  KeyRound,
  LogIn,
  LogOut,
  ShieldAlert,
  UserRound,
} from 'lucide-react';

// =============================================================================
// CLIENT-SIDE REACT APP - Contains vulnerabilities #1 and #4
// =============================================================================

// VULNERABILITY #4: Hardcoded client secret in front-end code.
// The client_secret should NEVER appear in JavaScript sent to the browser.
// Anyone can inspect the bundled React code and extract this value.
const APP_CONFIG = {
  clientId: 'course-insecure-app-demo',
  clientSecret: 'super-secret-client-secret-12345',
  redirectUri: 'http://localhost:5000/callback',
  authEndpoint: 'http://localhost:5000/mock-auth/authorize',
  tokenEndpoint: 'http://localhost:5000/mock-auth/token',
};

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || '';

function saveTokens(accessToken, idToken, refreshToken, expiresIn) {
  // VULNERABILITY #1: Tokens are stored in localStorage, which any JavaScript
  // on the page can read. An XSS bug would let an attacker steal every token.
  localStorage.setItem('access_token', accessToken);
  localStorage.setItem('id_token', idToken);
  localStorage.setItem('refresh_token', refreshToken);

  // The expiration time is saved but intentionally never enforced before use.
  const expiresAt = Date.now() + expiresIn * 1000;
  localStorage.setItem('token_expires_at', expiresAt.toString());
}

function getAccessToken() {
  // VULNERABILITY #1 continued: This returns the token even if it is expired.
  // A secure client would check token_expires_at, clear expired tokens, and
  // redirect the user to login or refresh the token safely.
  return localStorage.getItem('access_token');
}

function clearTokens() {
  localStorage.removeItem('access_token');
  localStorage.removeItem('id_token');
  localStorage.removeItem('refresh_token');
  localStorage.removeItem('token_expires_at');
}

function isLoggedIn() {
  // Only checks whether a token exists, not whether it is valid or expired.
  return Boolean(localStorage.getItem('access_token'));
}

function decodeJwt(token) {
  if (!token) return null;

  try {
    const payload = token.split('.')[1];
    const padded = payload.padEnd(payload.length + ((4 - (payload.length % 4)) % 4), '=');
    const json = atob(padded.replace(/-/g, '+').replace(/_/g, '/'));
    return JSON.parse(json);
  } catch {
    return null;
  }
}

function base64UrlEncode(value) {
  return btoa(value)
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
}

function createFakeJwt() {
  const header = base64UrlEncode(JSON.stringify({ alg: 'none', typ: 'JWT' }));
  const payload = base64UrlEncode(JSON.stringify({
    sub: 'hacker-99',
    name: 'Evil Hacker',
    email: 'hacker@example.com',
    role: 'admin',
    type: 'access',
  }));

  return `${header}.${payload}.fake-signature`;
}

function getStoredTokenInfo() {
  const token = getAccessToken();
  const decoded = decodeJwt(token);
  const expiresAt = Number(localStorage.getItem('token_expires_at'));

  return {
    token,
    decoded,
    expiresAt: Number.isFinite(expiresAt) ? expiresAt : null,
    loggedIn: isLoggedIn(),
  };
}

export default function App() {
  const [path, setPath] = useState(window.location.pathname);
  const [tokenInfo, setTokenInfo] = useState(getStoredTokenInfo);
  const [status, setStatus] = useState(null);
  const [apiResponse, setApiResponse] = useState(null);

  useEffect(() => {
    function onPopState() {
      setPath(window.location.pathname);
    }

    window.addEventListener('popstate', onPopState);
    return () => window.removeEventListener('popstate', onPopState);
  }, []);

  useEffect(() => {
    handleCallbackTokens();
    setTokenInfo(getStoredTokenInfo());

    const timer = window.setInterval(() => {
      setTokenInfo(getStoredTokenInfo());
    }, 1000);

    return () => window.clearInterval(timer);
  }, []);

  const route = useMemo(() => {
    if (path === '/dashboard') return 'dashboard';
    if (path === '/reports') return 'reports';
    return 'home';
  }, [path]);

  function navigate(nextPath) {
    window.history.pushState(null, '', nextPath);
    setPath(nextPath);
  }

  function handleCallbackTokens() {
    const hash = window.location.hash.substring(1);
    if (!hash) return;

    const params = new URLSearchParams(hash);
    const accessToken = params.get('access_token');
    const idToken = params.get('id_token');
    const refreshToken = params.get('refresh_token');
    const expiresIn = Number(params.get('expires_in') || 3600);

    if (accessToken) {
      saveTokens(accessToken, idToken, refreshToken, expiresIn);
      window.history.replaceState(null, '', window.location.pathname);
      setStatus({ type: 'success', message: 'Successfully logged in with the mock OAuth provider.' });
    }
  }

  function startLogin() {
    // The ASP.NET Core /login route starts the OAuth flow. It intentionally does
    // not send PKCE parameters; see backend/Program.cs for vulnerability #2.
    window.location.href = `${API_BASE_URL}/login`;
  }

  function logout() {
    clearTokens();
    setTokenInfo(getStoredTokenInfo());
    setApiResponse(null);
    navigate('/');
  }

  async function fetchProfile() {
    const token = getAccessToken();
    if (!token) {
      setStatus({ type: 'error', message: 'No access token found. Please log in.' });
      return;
    }

    try {
      const response = await fetch(`${API_BASE_URL}/api/user/profile`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      const data = await response.json();
      setApiResponse({ label: 'GET /api/user/profile - real token', data });
      setStatus({
        type: response.ok ? 'info' : 'error',
        message: response.ok ? 'Profile fetched from the unvalidated endpoint.' : `Error: ${data.error}`,
      });
    } catch (error) {
      setStatus({ type: 'error', message: `Request failed: ${error.message}` });
    }
  }

  async function fetchProtectedData() {
    const token = getAccessToken();
    if (!token) {
      setStatus({ type: 'error', message: 'No access token found. Please log in.' });
      return;
    }

    try {
      const response = await fetch(`${API_BASE_URL}/api/data`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${token}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ action: 'list_projects' }),
      });
      const data = await response.json();
      setApiResponse({ label: 'POST /api/data - validated endpoint', data });
      setStatus({
        type: response.ok ? 'success' : 'error',
        message: response.ok ? 'Protected data fetched successfully.' : `Error: ${data.error}`,
      });
    } catch (error) {
      setStatus({ type: 'error', message: `Request failed: ${error.message}` });
    }
  }

  async function fetchProfileWithFakeToken() {
    try {
      const response = await fetch(`${API_BASE_URL}/api/user/profile`, {
        headers: { Authorization: `Bearer ${createFakeJwt()}` },
      });
      const data = await response.json();
      setApiResponse({ label: 'GET /api/user/profile - forged token', data });
      setStatus({
        type: response.ok ? 'info' : 'error',
        message: response.ok
          ? 'The forged token was accepted by the unvalidated endpoint.'
          : `Error: ${data.error}`,
      });
    } catch (error) {
      setStatus({ type: 'error', message: `Request failed: ${error.message}` });
    }
  }

  return (
    <div className="app-shell">
      <header className="topbar">
        <div>
          <p className="eyebrow">CSC 436 Homework 5</p>
          <h1>Insecure Auth App</h1>
        </div>
        <nav aria-label="Main navigation">
          <button type="button" onClick={() => navigate('/')} className={route === 'home' ? 'active' : ''}>
            Home
          </button>
          <button type="button" onClick={() => navigate('/dashboard')} className={route === 'dashboard' ? 'active' : ''}>
            Dashboard
          </button>
          <button type="button" onClick={() => navigate('/reports')} className={route === 'reports' ? 'active' : ''}>
            Reports
          </button>
        </nav>
      </header>

      <main className="layout">
        <section className="warning-banner">
          <ShieldAlert size={20} aria-hidden="true" />
          <span>
            Educational starter app. It intentionally contains 5 authentication vulnerabilities for students to find and fix.
          </span>
        </section>

        {route === 'home' && (
          <HomeView
            tokenInfo={tokenInfo}
            status={status}
            onLogin={startLogin}
            onLogout={logout}
            onFetchProfile={fetchProfile}
            onFetchProtectedData={fetchProtectedData}
          />
        )}

        {route === 'dashboard' && (
          <DashboardView
            tokenInfo={tokenInfo}
            status={status}
            apiResponse={apiResponse}
            onLogout={logout}
            onFetchProfile={fetchProfile}
            onFetchProtectedData={fetchProtectedData}
            onFakeToken={fetchProfileWithFakeToken}
          />
        )}

        {route === 'reports' && (
          <ReportsView tokenInfo={tokenInfo} onLogin={startLogin} onLogout={logout} />
        )}
      </main>
    </div>
  );
}

function HomeView({ tokenInfo, status, onLogin, onLogout, onFetchProfile, onFetchProtectedData }) {
  return (
    <div className="grid two-columns">
      <section className="panel">
        <div className="panel-heading">
          <LogIn size={22} aria-hidden="true" />
          <h2>Mock OAuth Login</h2>
        </div>
        <p>
          Sign in with the simulated OAuth provider, then inspect the token handling and API behavior.
        </p>
        <div className="actions">
          {!tokenInfo.loggedIn ? (
            <button type="button" className="primary" onClick={onLogin}>
              <LogIn size={18} aria-hidden="true" />
              Log In with OAuth
            </button>
          ) : (
            <>
              <button type="button" className="primary" onClick={onFetchProfile}>
                <ClipboardList size={18} aria-hidden="true" />
                Fetch Profile
              </button>
              <button type="button" onClick={onFetchProtectedData}>
                <Box size={18} aria-hidden="true" />
                Fetch Data
              </button>
              <button type="button" className="danger" onClick={onLogout}>
                <LogOut size={18} aria-hidden="true" />
                Log Out
              </button>
            </>
          )}
        </div>
        {status && <StatusMessage status={status} />}
      </section>

      <TokenPanel tokenInfo={tokenInfo} compact />
    </div>
  );
}

function DashboardView({ tokenInfo, status, apiResponse, onLogout, onFetchProfile, onFetchProtectedData, onFakeToken }) {
  if (!tokenInfo.loggedIn) {
    return <LoginRequired />;
  }

  return (
    <div className="stack">
      <div className="grid two-columns">
        <UserPanel tokenInfo={tokenInfo} />
        <TokenPanel tokenInfo={tokenInfo} />
      </div>

      <section className="panel">
        <div className="panel-heading">
          <ClipboardList size={22} aria-hidden="true" />
          <h2>API Endpoints</h2>
        </div>
        <p className="muted">Compare the unvalidated profile endpoint with the endpoint that validates JWT signatures.</p>
        <div className="actions wrap">
          <button type="button" className="primary" onClick={onFetchProfile}>
            <UserRound size={18} aria-hidden="true" />
            GET /api/user/profile
          </button>
          <button type="button" className="primary" onClick={onFetchProtectedData}>
            <Box size={18} aria-hidden="true" />
            POST /api/data
          </button>
          <button type="button" className="danger" onClick={onFakeToken}>
            <ShieldAlert size={18} aria-hidden="true" />
            Fake Token Test
          </button>
          <button type="button" onClick={onLogout}>
            <LogOut size={18} aria-hidden="true" />
            Log Out
          </button>
        </div>
        <div className="vulnerability-note">
          Vulnerability #3: the fake token request succeeds because the profile endpoint decodes the JWT without verifying its signature.
        </div>
        {status && <StatusMessage status={status} />}
        {apiResponse && <ApiResponse response={apiResponse} />}
      </section>

      <VulnerabilityChecklist />
    </div>
  );
}

function ReportsView({ tokenInfo, onLogin, onLogout }) {
  if (!tokenInfo.loggedIn) {
    return <LoginRequired onLogin={onLogin} />;
  }

  return (
    <section className="panel">
      <div className="panel-heading">
        <KeyRound size={22} aria-hidden="true" />
        <h2>Reports</h2>
      </div>
      <p className="muted">
        This second protected React route uses the same weak client-side guard: it only checks for a token in localStorage.
      </p>
      <table>
        <tbody>
          <tr><th>Report</th><th>Status</th><th>Owner</th></tr>
          <tr><td>OAuth audit</td><td><span className="badge yellow">Needs review</span></td><td>{tokenInfo.decoded?.name || 'Unknown'}</td></tr>
          <tr><td>Token storage</td><td><span className="badge red">Vulnerable</span></td><td>Security team</td></tr>
          <tr><td>API access control</td><td><span className="badge red">Vulnerable</span></td><td>Security team</td></tr>
        </tbody>
      </table>
      <div className="actions">
        <button type="button" onClick={onLogout}>
          <LogOut size={18} aria-hidden="true" />
          Log Out
        </button>
      </div>
    </section>
  );
}

function LoginRequired({ onLogin }) {
  return (
    <section className="panel narrow">
      <div className="panel-heading">
        <ShieldAlert size={22} aria-hidden="true" />
        <h2>Login Required</h2>
      </div>
      <p>This route is hidden unless localStorage contains an access token.</p>
      {onLogin && (
        <button type="button" className="primary" onClick={onLogin}>
          <LogIn size={18} aria-hidden="true" />
          Log In
        </button>
      )}
    </section>
  );
}

function UserPanel({ tokenInfo }) {
  const user = tokenInfo.decoded || {};

  return (
    <section className="panel">
      <div className="panel-heading">
        <UserRound size={22} aria-hidden="true" />
        <h2>User Information</h2>
      </div>
      <table>
        <tbody>
          <tr><th>Name</th><td>{user.name || '-'}</td></tr>
          <tr><th>Email</th><td>{user.email || '-'}</td></tr>
          <tr><th>Role</th><td>{user.role || '-'}</td></tr>
          <tr><th>User ID</th><td>{user.sub || '-'}</td></tr>
        </tbody>
      </table>
    </section>
  );
}

function TokenPanel({ tokenInfo, compact = false }) {
  const decoded = tokenInfo.decoded;
  const expiresAt = tokenInfo.expiresAt;
  const isExpired = expiresAt ? Date.now() > expiresAt : false;
  const secondsRemaining = decoded?.exp ? decoded.exp - Math.floor(Date.now() / 1000) : null;

  return (
    <section className="panel">
      <div className="panel-heading">
        <KeyRound size={22} aria-hidden="true" />
        <h2>Token Status</h2>
      </div>
      {!tokenInfo.loggedIn ? (
        <p>No token is currently stored.</p>
      ) : (
        <>
          <table>
            <tbody>
              <tr><th>Status</th><td><span className={`badge ${isExpired ? 'red' : 'green'}`}>{isExpired ? 'Expired' : 'Present'}</span></td></tr>
              <tr><th>Issued At</th><td>{decoded?.iat ? new Date(decoded.iat * 1000).toLocaleString() : '-'}</td></tr>
              <tr><th>Expires At</th><td>{decoded?.exp ? new Date(decoded.exp * 1000).toLocaleString() : '-'}</td></tr>
              {!compact && <tr><th>Time Remaining</th><td>{secondsRemaining === null ? '-' : `${Math.max(secondsRemaining, 0)} seconds`}</td></tr>}
            </tbody>
          </table>
          <div className="token-preview">{tokenInfo.token?.slice(0, 96)}...</div>
          <div className="vulnerability-note">
            Vulnerability #1: the app displays expiration data but never checks it before sending API requests.
          </div>
        </>
      )}
    </section>
  );
}

function VulnerabilityChecklist() {
  const rows = [
    ['1', 'JWT in localStorage, no expiration check', 'frontend/src/App.jsx'],
    ['2', 'Missing PKCE in OAuth flow', 'backend/Program.cs'],
    ['3', 'Unvalidated API endpoint', 'backend/Program.cs'],
    ['4', 'Client secret in front-end code', 'frontend/src/App.jsx'],
    ['5', 'Missing HTTPS redirect and HSTS', 'backend/Program.cs'],
  ];

  return (
    <section className="panel">
      <div className="panel-heading">
        <ShieldAlert size={22} aria-hidden="true" />
        <h2>Vulnerability Checklist</h2>
      </div>
      <table>
        <tbody>
          <tr><th>#</th><th>Vulnerability</th><th>Starter Location</th></tr>
          {rows.map(([id, title, location]) => (
            <tr key={id}>
              <td>{id}</td>
              <td>{title}</td>
              <td><code>{location}</code></td>
            </tr>
          ))}
        </tbody>
      </table>
    </section>
  );
}

function StatusMessage({ status }) {
  return <div className={`status ${status.type}`}>{status.message}</div>;
}

function ApiResponse({ response }) {
  return (
    <pre className="api-response">{`// ${response.label}\n${JSON.stringify(response.data, null, 2)}`}</pre>
  );
}

void APP_CONFIG;
