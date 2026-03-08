/**
 * Carrot in a Box - itch.io OAuth Server
 * Node.js/Express backend handling OAuth 2.0 flow with itch.io
 * 
 * Setup:
 *   npm install express cors dotenv node-fetch express-session
 *   node server.js
 */

const express = require('express');
const cors = require('cors');
const session = require('express-session');
require('dotenv').config();

const app = express();
app.use(express.json());
app.use(cors({
  origin: process.env.UNITY_CLIENT_ORIGIN || 'http://localhost:8080',
  credentials: true
}));
app.use(session({
  secret: process.env.SESSION_SECRET || 'carrot-box-secret-change-me',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: process.env.NODE_ENV === 'production', maxAge: 24 * 60 * 60 * 1000 }
}));

// ─── itch.io OAuth Config ────────────────────────────────────────────────────
const ITCH_CLIENT_ID     = process.env.ITCH_CLIENT_ID;       // From itch.io developer settings
const ITCH_CLIENT_SECRET = process.env.ITCH_CLIENT_SECRET;   // From itch.io developer settings
const REDIRECT_URI       = process.env.REDIRECT_URI || 'http://localhost:3000/auth/callback';

// In-memory store — replace with a real DB (MongoDB, SQLite, etc.) for production
const users = new Map(); // itchId → { itchId, itchUsername, displayName, accessToken, wins, gamesPlayed, reports }

// ─── STEP 1: Build Authorization URL ────────────────────────────────────────
// Unity calls this endpoint, opens the URL in the system browser
app.get('/auth/login', (req, res) => {
  const state = Math.random().toString(36).substring(2); // CSRF protection
  req.session.oauthState = state;

  const params = new URLSearchParams({
    client_id:     ITCH_CLIENT_ID,
    redirect_uri:  REDIRECT_URI,
    response_type: 'code',
    scope:         'profile',
    state:         state
  });

  const authUrl = `https://itch.io/user/oauth?${params}`;
  res.json({ authUrl, state });
});

// ─── STEP 2: Handle Callback from itch.io ───────────────────────────────────
// itch.io redirects the browser here after the user approves
app.get('/auth/callback', async (req, res) => {
  const { code, state, error } = req.query;

  if (error) {
    return res.redirect(`carrotbox://auth?error=${encodeURIComponent(error)}`);
  }

  // Validate state to prevent CSRF
  if (state !== req.session.oauthState) {
    return res.status(400).send('Invalid state parameter. Possible CSRF attack.');
  }

  try {
    // Exchange code for access token
    const tokenRes = await fetch('https://itch.io/api/1/oauth2/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id:     ITCH_CLIENT_ID,
        client_secret: ITCH_CLIENT_SECRET,
        grant_type:    'authorization_code',
        code,
        redirect_uri:  REDIRECT_URI
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

    // Upsert user in our store
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

    // Create a session token for Unity to use
    const sessionToken = Buffer.from(`${itchUser.id}:${Date.now()}:${Math.random()}`).toString('base64');
    req.session.sessionToken = sessionToken;
    req.session.itchId = itchUser.id;

    // Redirect back to Unity via custom URI scheme OR show success page
    // Unity should register "carrotbox" as a custom URI scheme
    const redirectUrl = process.env.USE_DEEP_LINK === 'true'
      ? `carrotbox://auth?token=${sessionToken}&username=${encodeURIComponent(itchUser.username)}`
      : `/auth/success?token=${sessionToken}`;

    res.redirect(redirectUrl);
  } catch (err) {
    console.error('OAuth error:', err);
    res.redirect(`/auth/error?message=${encodeURIComponent(err.message)}`);
  }
});

// ─── STEP 3: Success Page (Unity polls this or reads via deep link) ──────────
app.get('/auth/success', (req, res) => {
  const token = req.query.token;
  // Show a simple page that Unity's embedded browser or polling can detect
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
        // Signal Unity if using Unity WebView
        if (window.vuplex) { window.vuplex.postMessage(JSON.stringify({ type: 'AUTH_SUCCESS', token: '${token}' })); }
        // Also try to close the window after a short delay
        setTimeout(() => window.close(), 2000);
      </script>
    </body>
    </html>
  `);
});

// ─── Validate Session Token (Unity polls this after redirect) ───────────────
app.post('/auth/validate', (req, res) => {
  const { token } = req.body;
  if (!token) return res.status(400).json({ error: 'No token provided' });

  // Find user with this token (in production, store token→userId mapping)
  let foundUser = null;
  for (const [, user] of users) {
    if (req.session.sessionToken === token && req.session.itchId === user.itchId) {
      foundUser = user;
      break;
    }
  }

  if (!foundUser) return res.status(401).json({ error: 'Invalid or expired token' });
  if (foundUser.isBanned) return res.status(403).json({ error: 'Account banned', reason: 'Too many reports' });

  res.json({
    success:      true,
    itchId:       foundUser.itchId,
    itchUsername: foundUser.itchUsername,
    displayName:  foundUser.displayName,
    wins:         foundUser.wins,
    gamesPlayed:  foundUser.gamesPlayed
  });
});

// ─── Update Display Name ─────────────────────────────────────────────────────
app.post('/user/display-name', requireAuth, (req, res) => {
  const { displayName } = req.body;
  if (!displayName || displayName.length < 2 || displayName.length > 24) {
    return res.status(400).json({ error: 'Display name must be 2–24 characters' });
  }
  // Sanitize
  const clean = displayName.replace(/[<>"']/g, '').trim();
  const user = users.get(req.itchId);
  user.displayName = clean;
  res.json({ success: true, displayName: clean });
});

// ─── Get Leaderboard ─────────────────────────────────────────────────────────
app.get('/leaderboard', (req, res) => {
  const entries = [];
  for (const [, user] of users) {
    if (user.isBanned || user.gamesPlayed === 0) continue;
    const winRate = user.wins / user.gamesPlayed;
    entries.push({
      displayName: user.displayName,
      wins:        user.wins,
      gamesPlayed: user.gamesPlayed,
      winRate:     Math.round(winRate * 1000) / 1000  // 3 decimal places
    });
  }
  entries.sort((a, b) => b.winRate - a.winRate);
  res.json({ leaderboard: entries.slice(0, 50) });
});

// ─── Lobby: Online Player Count ──────────────────────────────────────────────
// In production this would be tracked via WebSocket connections
const onlinePlayers = new Set();
app.get('/lobby/online', (req, res) => {
  res.json({ onlineCount: onlinePlayers.size });
});

// ─── Record Game Result ──────────────────────────────────────────────────────
app.post('/game/result', requireAuth, (req, res) => {
  const { won } = req.body;
  const user = users.get(req.itchId);
  user.gamesPlayed++;
  if (won) user.wins++;
  res.json({ success: true, wins: user.wins, gamesPlayed: user.gamesPlayed });
});

// ─── Logout ───────────────────────────────────────────────────────────────────
app.post('/auth/logout', (req, res) => {
  req.session.destroy();
  res.json({ success: true });
});

// ─── Auth Middleware ──────────────────────────────────────────────────────────
function requireAuth(req, res, next) {
  if (!req.session.itchId) return res.status(401).json({ error: 'Not authenticated' });
  req.itchId = req.session.itchId;
  if (!users.has(req.itchId)) return res.status(401).json({ error: 'User not found' });
  next();
}

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🥕 Carrot OAuth server running on port ${PORT}`));
