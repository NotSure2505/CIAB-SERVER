/**
 * Carrot in a Box - itch.io OAuth Server
 * Node.js/Express backend handling OAuth 2.0 flow with itch.io (PKCE)
 * State + codeVerifier are stored in a server-side Map to avoid session issues
 */

const express = require('express');
const cors = require('cors');
const session = require('express-session');
const crypto = require('crypto');
require('dotenv').config();

const app = express();
app.use(express.json());
app.use(cors({ origin: '*', credentials: true }));
app.use(session({
  secret: process.env.SESSION_SECRET || 'carrot-box-secret-change-me',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
    maxAge: 24 * 60 * 60 * 1000
  }
}));

// ─── In-memory stores ─────────────────────────────────────────────────────────
const users = new Map();         // itchId → user object
const pendingAuth = new Map();   // state → { codeVerifier, createdAt }
const sessionTokens = new Map(); // token → itchId

// Clean up expired pending auths every 5 minutes
setInterval(() => {
  const fiveMinutesAgo = Date.now() - 5 * 60 * 1000;
  for (const [state, data] of pendingAuth) {
    if (data.createdAt < fiveMinutesAgo) pendingAuth.delete(state);
  }
}, 5 * 60 * 1000);

// ─── STEP 1: Build Authorization URL ────────────────────────────────────────
app.get('/auth/login', (req, res) => {
  const state = crypto.randomBytes(16).toString('hex');

  // Generate PKCE
  const codeVerifier = crypto.randomBytes(32).toString('base64url');
  const codeChallenge = crypto
    .createHash('sha256')
    .update(codeVerifier)
    .digest('base64url');

  // Store codeVerifier in server-side map keyed by state (avoids session cookie issues)
  pendingAuth.set(state, { codeVerifier, createdAt: Date.now() });

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
  console.log(`[Auth] Login initiated, state: ${state}`);
  res.json({ authUrl, state });
});

// ─── STEP 2: Handle Callback from itch.io ───────────────────────────────────
app.get('/auth/callback', async (req, res) => {
  const { code, state, error } = req.query;

  if (error) {
    console.error('[Auth] itch.io returned error:', error);
    return res.redirect(`/auth/error?message=${encodeURIComponent(error)}`);
  }

  // Look up codeVerifier from server-side map (no session needed)
  const pending = pendingAuth.get(state);
  if (!pending) {
    console.error('[Auth] State not found:', state);
    return res.redirect('/auth/error?message=Login+session+expired.+Please+try+again.');
  }

  pendingAuth.delete(state);

  try {
    // itch.io sends the access token directly as the `code` parameter
    // There is no token exchange step — the code IS the access token
    const accessToken = code;
    console.log('[Auth] Using code directly as access token');

    // Fetch user profile
    const profileRes = await fetch('https://itch.io/api/1/me', {
      headers: { Authorization: `Bearer ${accessToken}` }
    });
    const profileText = await profileRes.text();
    console.log('[Auth] Profile raw response:', profileText.substring(0, 200));

    let profile;
    try {
      profile = JSON.parse(profileText);
    } catch (e) {
      throw new Error('Could not parse profile response from itch.io');
    }

    if (profile.errors) throw new Error(profile.errors.join(', '));
    const itchUser = profile.user;

    console.log(`[Auth] Logged in: ${itchUser.username} (id: ${itchUser.id})`);

    // Upsert user
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

    // Create session token
    const sessionToken = crypto.randomBytes(32).toString('hex');
    sessionTokens.set(sessionToken, itchUser.id);
    req.session.sessionToken = sessionToken;
    req.session.itchId = itchUser.id;

    const redirectUrl = process.env.USE_DEEP_LINK === 'true'
      ? `carrotbox://auth?token=${sessionToken}&username=${encodeURIComponent(itchUser.username)}`
      : `/auth/success?token=${sessionToken}&username=${encodeURIComponent(itchUser.display_name || itchUser.username)}`;

    res.redirect(redirectUrl);
  } catch (err) {
    console.error('[Auth] OAuth error:', err);
    res.redirect(`/auth/error?message=${encodeURIComponent(err.message)}`);
  }
});

// ─── Success Page ─────────────────────────────────────────────────────────────
app.get('/auth/success', (req, res) => {
  const { token, username } = req.query;
  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>Carrot in a Box - Login Successful</title>
      <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: sans-serif; display: flex; align-items: center; justify-content: center;
               min-height: 100vh; background: #1a1a2e; color: #e94560; flex-direction: column; gap: 16px; }
        h1 { font-size: 2rem; }
        p { color: #ccc; font-size: 1.1rem; }
      </style>
    </head>
    <body>
      <h1>🥕 Welcome, ${username}!</h1>
      <p>Login successful. You can close this window and return to Carrot in a Box.</p>
      <script>
        if (window.opener) {
          window.opener.postMessage(JSON.stringify({ type: 'AUTH_SUCCESS', token: '${token}' }), '*');
        }
        setTimeout(() => window.close(), 3000);
      </script>
    </body>
    </html>
  `);
});

// ─── Error Page ───────────────────────────────────────────────────────────────
app.get('/auth/error', (req, res) => {
  const message = req.query.message || 'Unknown error occurred';
  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>Login Error</title>
      <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: sans-serif; display: flex; align-items: center; justify-content: center;
               min-height: 100vh; background: #1a1a2e; color: #e94560; flex-direction: column; gap: 16px; }
        p { color: #ccc; }
      </style>
    </head>
    <body>
      <h1>Login Failed</h1>
      <p>${message}</p>
      <p>Please close this window and try again.</p>
    </body>
    </html>
  `);
});

// ─── Poll (Unity polls after opening browser) ────────────────────────────────
app.get('/auth/poll', (req, res) => {
  if (req.session && req.session.sessionToken) {
    res.json({ ready: true, token: req.session.sessionToken });
  } else {
    res.json({ ready: false });
  }
});

// ─── Validate Token ───────────────────────────────────────────────────────────
app.post('/auth/validate', (req, res) => {
  const { token } = req.body;
  if (!token) return res.status(400).json({ error: 'No token provided' });

  const itchId = sessionTokens.get(token);
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
  for (const [, user] of users) {
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
    sessionTokens.delete(req.session.sessionToken);
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
  const authHeader = req.headers.authorization;
  const token = authHeader ? authHeader.replace('Bearer ', '') : req.body?.token;
  if (!token) return res.status(401).json({ error: 'Not authenticated' });

  const itchId = sessionTokens.get(token);
  if (!itchId) return res.status(401).json({ error: 'Invalid token' });

  req.itchId = itchId;
  next();
}

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🥕 Carrot OAuth server running on port ${PORT}`));
