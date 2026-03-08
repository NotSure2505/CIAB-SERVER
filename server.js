/**
 * Carrot in a Box - itch.io OAuth Server
 * Node.js/Express backend handling OAuth 2.0 flow with itch.io (PKCE)
 */

const express = require('express');
const cors = require('cors');
const session = require('express-session');
const crypto = require('crypto');
require('dotenv').config();

const app = express();
app.use(express.json());
app.use(cors({
  origin: process.env.UNITY_CLIENT_ORIGIN || '*',
  credentials: true
}));
app.use(session({
  secret: process.env.SESSION_SECRET || 'carrot-box-secret-change-me',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: process.env.NODE_ENV === 'production', maxAge: 24 * 60 * 60 * 1000 }
}));

// ─── In-memory user store ────────────────────────────────────────────────────
// Replace with a real DB for production
const users = new Map();

// ─── STEP 1: Build Authorization URL ────────────────────────────────────────
app.get('/auth/login', (req, res) => {
  const state = crypto.randomBytes(16).toString('hex');

  // Generate PKCE code verifier and challenge
  const codeVerifier = crypto.randomBytes(32).toString('base64url');
  const codeChallenge = crypto
    .createHash('sha256')
    .update(codeVerifier)
    .digest('base64url');

  req.session.oauthState = state;
  req.session.codeVerifier = codeVerifier;

  const params = new URLSearchParams({
    client_id:             process.env.ITCH_CLIENT_ID,
    redirect_uri:          process.env.REDIRECT_URI,
    response_type:         'code',
    scope:                 'profile',
    state:                 state,
    code_challenge:        codeChallenge,
    code_challenge_method: 'S256'
  });

  const authUrl = `https://itch.io/user/oauth?${params}`;
  res.json({ authUrl, state });
});

// ─── STEP 2: Handle Callback from itch.io ───────────────────────────────────
app.get('/auth/callback', async (req, res) => {
  const { code, state, error } = req.query;

  if (error) {
    return res.redirect(`/auth/error?message=${encodeURIComponent(error)}`);
  }

  if (state !== req.session.oauthState) {
    return res.status(400).send('Invalid state parameter. Possible CSRF attack.');
  }

  try {
    // Exchange code for access token (with PKCE verifier)
    const tokenRes = await fetch('https://itch.io/api/1/oauth2/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id:     process.env.ITCH_CLIENT_ID,
        client_secret: process.env.ITCH_CLIENT_SECRET,
        grant_type:    'authorization_code',
        code,
        redirect_uri:  process.env.REDIRECT_URI,
        code_verifier: req.session.codeVerifier
      })
    });

    const tokenData = await tokenRes.json();
    if (tokenData.error) throw new Error(tokenData.error_description || tokenData.error);

    const accessToken = tokenData.access_token;

    // Fetch user profile from itch.io
    const profileRes = await fetch('https://itch.io/api/1/me', {
      headers: { Authorization: `Bearer ${accessToken}` }
    });
    const profile = await profileRes.json();
    const itchUser = profile.user;

    // Upsert user in store
    let user = users.get(itchUser.id);
    if (!user) {
      user = {
        itchId:       itchUser.id,
        itchUsername: itchUser.username,
        displayName:  itchUser.display_name || itchUser.username,
        accessToken,
        wins:         0,
        gamesPlayed:  0,
        reports:      0,
        isBanned:     false,
        createdAt:    new Date().toISOString()
      };
    } else {
      user.accessToken = accessToken;
      user.itchUsername = itchUser.username;
    }
    users.set(itchUser.id, user);

    // Create session token for Unity
    const sessionToken = crypto.randomBytes(32).toString('hex');
    req.session.sessionToken = sessionToken;
    req.session.itchId = itchUser.id;

    // Store token → userId mapping for validation
    users.set(`token:${sessionToken}`, itchUser.id);

    const redirectUrl = process.env.USE_DEEP_LINK === 'true'
      ? `carrotbox://auth?token=${sessionToken}&username=${encodeURIComponent(itchUser.username)}`
      : `/auth/success?token=${sessionToken}`;

    res.redirect(redirectUrl);
  } catch (err) {
    console.error('OAuth error:', err);
    res.redirect(`/auth/error?message=${encodeURIComponent(err.message)}`);
  }
});

// ─── STEP 3: Success Page ────────────────────────────────────────────────────
app.get('/auth/success', (req, res) => {
  const token = req.query.token;
  res.send(`
    <!DOCTYPE html>
    <html>
    <head><title>Carrot in a Box - Login Successful</title>
    <style>
      body { font-family: sans-serif; display:flex; align-items:center; justify-content:center;
             min-height:100vh; margin:0; background:#1a1a2e; color:#e94560; flex-direction:column; }
      h1 { font-size: 2rem; }
      p { color: #ccc; }
    </style>
    </head>
    <body>
      <h1>🥕 Login Successful!</h1>
      <p>You can close this window and return to Carrot in a Box.</p>
      <script>
        if (window.opener) {
          window.opener.postMessage(JSON.stringify({ type: 'AUTH_SUCCESS', token: '${token}' }), '*');
        }
        setTimeout(() => window.close(), 2000);
      </script>
    </body>
    </html>
  `);
});

// ─── Error Page ───────────────────────────────────────────────────────────────
app.get('/auth/error', (req, res) => {
  const message = req.query.message || 'Unknown error';
  res.send(`
    <!DOCTYPE html>
    <html>
    <head><title>Login Error</title>
    <style>
      body { font-family: sans-serif; display:flex; align-items:center; justify-content:center;
             min-height:100vh; margin:0; background:#1a1a2e; color:#e94560; flex-direction:column; }
    </style>
    </head>
    <body>
      <h1>Login Failed</h1>
      <p style="color:#ccc">${message}</p>
      <p style="color:#ccc">Please close this window and try again.</p>
    </body>
    </html>
  `);
});

// ─── Poll endpoint (Unity polls this after opening browser) ─────────────────
app.get('/auth/poll', (req, res) => {
  if (req.session.sessionToken) {
    res.json({ ready: true, token: req.session.sessionToken });
  } else {
    res.json({ ready: false });
  }
});

// ─── Validate Token ───────────────────────────────────────────────────────────
app.post('/auth/validate', (req, res) => {
  const { token } = req.body;
  if (!token) return res.status(400).json({ error: 'No token provided' });

  const itchId = users.get(`token:${token}`);
  if (!itchId) return res.status(401).json({ error: 'Invalid or expired token' });

  const user = users.get(itchId);
  if (!user) return res.status(401).json({ error: 'User not found' });
  if (user.isBanned) return res.status(403).json({ error: 'Account banned' });

  res.json({
    success:      true,
    itchId:       user.itchId,
    itchUsername: user.itchUsername,
    displayName:  user.displayName,
    wins:         user.wins,
    gamesPlayed:  user.gamesPlayed
  });
});

// ─── Update Display Name ──────────────────────────────────────────────────────
app.post('/user/display-name', requireAuth, (req, res) => {
  const { displayName } = req.body;
  if (!displayName || displayName.length < 2 || displayName.length > 24) {
    return res.status(400).json({ error: 'Display name must be 2-24 characters' });
  }
  const clean = displayName.replace(/[<>"']/g, '').trim();
  const user = users.get(req.itchId);
  user.displayName = clean;
  res.json({ success: true, displayName: clean });
});

// ─── Leaderboard ──────────────────────────────────────────────────────────────
app.get('/leaderboard', (req, res) => {
  const entries = [];
  for (const [key, user] of users) {
    if (key.startsWith('token:')) continue;
    if (user.isBanned || user.gamesPlayed === 0) continue;
    entries.push({
      displayName: user.displayName,
      wins:        user.wins,
      gamesPlayed: user.gamesPlayed,
      winRate:     Math.round((user.wins / user.gamesPlayed) * 1000) / 1000
    });
  }
  entries.sort((a, b) => b.winRate - a.winRate);
  res.json({ leaderboard: entries.slice(0, 50) });
});

// ─── Online Count ─────────────────────────────────────────────────────────────
const onlinePlayers = new Set();
app.get('/lobby/online', (req, res) => {
  res.json({ onlineCount: onlinePlayers.size });
});

// ─── Record Game Result ───────────────────────────────────────────────────────
app.post('/game/result', requireAuth, (req, res) => {
  const { won } = req.body;
  const user = users.get(req.itchId);
  user.gamesPlayed++;
  if (won) user.wins++;
  res.json({ success: true, wins: user.wins, gamesPlayed: user.gamesPlayed });
});

// ─── Logout ───────────────────────────────────────────────────────────────────
app.post('/auth/logout', (req, res) => {
  if (req.session.sessionToken) {
    users.delete(`token:${req.session.sessionToken}`);
  }
  req.session.destroy();
  res.json({ success: true });
});

// ─── Health Check ─────────────────────────────────────────────────────────────
app.get('/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// ─── Auth Middleware ──────────────────────────────────────────────────────────
function requireAuth(req, res, next) {
  const token = req.headers.authorization?.replace('Bearer ', '') || req.body.token;
  if (!token) return res.status(401).json({ error: 'Not authenticated' });

  const itchId = users.get(`token:${token}`);
  if (!itchId) return res.status(401).json({ error: 'Invalid token' });

  req.itchId = itchId;
  next();
}

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🥕 Carrot OAuth server running on port ${PORT}`));
