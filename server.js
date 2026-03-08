/**
 * Carrot in a Box - itch.io OAuth Server
 * Node.js/Express backend handling OAuth 2.0 flow with itch.io (PKCE)
 * State + codeVerifier are stored in a server-side Map to avoid session issues
 */

const express    = require('express');
const cors       = require('cors');
const crypto     = require('crypto');
const { Server } = require('socket.io');
const http       = require('http');
require('dotenv').config();

const app    = express();
const server = http.createServer(app);
const io     = new Server(server, {
  cors: { origin: '*', methods: ['GET', 'POST'] }
});

app.use(express.json());
app.use(cors({ origin: '*', credentials: true }));

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
    // Exchange code for access token using correct itch.io endpoint
    console.log('[Auth] Exchanging code for token...');
    const tokenRes = await fetch('https://api.itch.io/oauth/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id:     process.env.ITCH_CLIENT_ID,
        grant_type:    'authorization_code',
        code,
        code_verifier: pending.codeVerifier,
        redirect_uri:  process.env.REDIRECT_URI
      })
    });

    const rawToken = await tokenRes.text();
    console.log('[Auth] Token response:', rawToken.substring(0, 300));

    let tokenData;
    try {
      tokenData = JSON.parse(rawToken);
    } catch (e) {
      throw new Error(`Token exchange failed: ${rawToken.substring(0, 100)}`);
    }

    if (tokenData.errors) throw new Error(tokenData.errors.join(', '));

    const accessToken = tokenData.access_token;
    if (!accessToken) throw new Error('No access token in response: ' + JSON.stringify(tokenData));

    // itch.io token response includes user_id directly in key object
    // Use it to fetch profile via the correct endpoint
    const userId = tokenData.key?.user_id;
    console.log(`[Auth] Got access token for user_id: ${userId}, fetching profile...`);

    const profileRes = await fetch("https://itch.io/api/1/key/me", { headers: { Authorization: `Bearer ${accessToken}` } });
    const profileText = await profileRes.text();
    console.log('[Auth] Profile response:', profileText.substring(0, 300));

    let profile;
    try {
      profile = JSON.parse(profileText);
    } catch (e) {
      throw new Error('Could not parse profile response');
    }

    // Build itchUser from whatever we have
    // If profile endpoint fails, fall back to token data
    const itchUser = profile.user || {
      id:           userId,
      username:     `user_${userId}`,
      display_name: `Player_${userId}`
    };

    console.log('[Auth] User:', JSON.stringify(itchUser));

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
  // Poll is handled via token passed in query
  res.json({ ready: false });
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

// ─── CRS (Carrot Rating System) ──────────────────────────────────────────────
const CRS_K = 10; // Smoothing constant — penalises low game counts

function calcCRS(wins, gamesPlayed) {
  if (gamesPlayed === 0) return 0;
  return Math.round((wins / (gamesPlayed + CRS_K)) * 1000);
}

function getCarrotRank(crs) {
  if (crs >= 900) return { rank: 'Carrot Legend',  emoji: '👑',      tier: 6 };
  if (crs >= 750) return { rank: 'Carrot Master',  emoji: '🥕🥕🥕',  tier: 5 };
  if (crs >= 600) return { rank: 'Carrot Hoarder', emoji: '🥕🥕',    tier: 4 };
  if (crs >= 450) return { rank: 'Carrot Finder',  emoji: '🥕',      tier: 3 };
  if (crs >= 250) return { rank: 'Digger',         emoji: '🐇',      tier: 2 };
  if (crs >= 100) return { rank: 'Sprout',         emoji: '🌿',      tier: 1 };
  return           { rank: 'Seedling',             emoji: '🌱',      tier: 0 };
}

// ─── Leaderboard ──────────────────────────────────────────────────────────────
app.get('/leaderboard', (req, res) => {
  const entries = [];
  for (const [, user] of users) {
    if (user.isBanned || user.gamesPlayed === 0) continue;
    const crs      = calcCRS(user.wins, user.gamesPlayed);
    const rankInfo = getCarrotRank(crs);
    entries.push({
      displayName: user.displayName,
      wins:        user.wins,
      gamesPlayed: user.gamesPlayed,
      losses:      user.gamesPlayed - user.wins,
      winRate:     Math.round((user.wins / user.gamesPlayed) * 1000) / 1000,
      crs,
      rank:        rankInfo.rank,
      rankEmoji:   rankInfo.emoji,
      tier:        rankInfo.tier
    });
  }
  entries.sort((a, b) => b.crs - a.crs);
  res.json({ leaderboard: entries.slice(0, 50) });
});

// ─── Player CRS (single player lookup) ───────────────────────────────────────
app.get('/player/crs', requireAuth, (req, res) => {
  const user     = users.get(req.itchId);
  const crs      = calcCRS(user.wins, user.gamesPlayed);
  const rankInfo = getCarrotRank(crs);
  res.json({
    displayName: user.displayName,
    wins:        user.wins,
    gamesPlayed: user.gamesPlayed,
    losses:      user.gamesPlayed - user.wins,
    crs,
    rank:        rankInfo.rank,
    rankEmoji:   rankInfo.emoji,
    tier:        rankInfo.tier
  });
});

// ─── Online Count (REST fallback) ────────────────────────────────────────────
app.get('/lobby/online', (req, res) => {
  res.json({ onlineCount: connectedPlayers.size });
});

// ─── Invite Links ─────────────────────────────────────────────────────────────
const inviteCodes = new Map(); // code → { itchId, roomId, createdAt }

app.post('/invite/create', requireAuth, (req, res) => {
  const code    = crypto.randomBytes(6).toString('hex'); // e.g. "a3f9c2"
  const roomId  = `room_${crypto.randomBytes(8).toString('hex')}`;
  inviteCodes.set(code, {
    itchId:    req.itchId,
    roomId,
    createdAt: Date.now()
  });
  // Invite link goes to itch.io game page with code in hash
  const inviteUrl = `https://notsure2505.itch.io/carrot-in-a-box#invite=${code}`;
  res.json({ code, roomId, inviteUrl });
});

app.get('/invite/:code', (req, res) => {
  const invite = inviteCodes.get(req.params.code);
  if (!invite) return res.status(404).json({ error: 'Invite not found or expired' });
  const age = Date.now() - invite.createdAt;
  if (age > 10 * 60 * 1000) { // 10 min expiry
    inviteCodes.delete(req.params.code);
    return res.status(410).json({ error: 'Invite expired' });
  }
  const host = users.get(invite.itchId);
  res.json({
    valid:       true,
    roomId:      invite.roomId,
    hostName:    host?.displayName || 'Unknown',
    code:        req.params.code
  });
});

// Clean up expired invites every 10 minutes
setInterval(() => {
  const tenMinutesAgo = Date.now() - 10 * 60 * 1000;
  for (const [code, invite] of inviteCodes) {
    if (invite.createdAt < tenMinutesAgo) inviteCodes.delete(code);
  }
}, 10 * 60 * 1000);

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
  // token cleanup handled via body token

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

// ─── Socket.io — Real-time Matchmaking ───────────────────────────────────────
const connectedPlayers = new Map(); // socketId → { itchId, displayName, inQueue, roomId }
const matchQueue       = [];        // array of socketIds waiting for a match
const activeRooms      = new Map(); // roomId → { players: [socketId, socketId], state }

io.on('connection', (socket) => {
  console.log(`[Socket] Client connected: ${socket.id}`);
  connectedPlayers.set(socket.id, { itchId: null, displayName: null, inQueue: false, roomId: null });

  // Broadcast updated online count to everyone
  io.emit('online_count', connectedPlayers.size);

  // ── Authenticate socket ──────────────────────────────────────────────────
  socket.on('authenticate', (token) => {
    const itchId = sessionTokens.get(token);
    if (!itchId) { socket.emit('auth_error', 'Invalid token'); return; }
    const user = users.get(itchId);
    if (!user)  { socket.emit('auth_error', 'User not found'); return; }

    const player = connectedPlayers.get(socket.id);
    player.itchId      = itchId;
    player.displayName = user.displayName;
    socket.emit('authenticated', { displayName: user.displayName });
    console.log(`[Socket] Authenticated: ${user.displayName}`);
  });

  // ── Join matchmaking queue ───────────────────────────────────────────────
  socket.on('join_queue', () => {
    const player = connectedPlayers.get(socket.id);
    if (!player?.itchId) { socket.emit('error', 'Not authenticated'); return; }
    if (player.inQueue)  { return; } // already in queue

    player.inQueue = true;
    matchQueue.push(socket.id);
    socket.emit('queue_joined', { position: matchQueue.length });
    io.emit('online_count', connectedPlayers.size);

    console.log(`[Queue] ${player.displayName} joined. Queue size: ${matchQueue.length}`);

    // Try to make a match
    tryMakeMatch();
  });

  // ── Leave matchmaking queue ──────────────────────────────────────────────
  socket.on('leave_queue', () => {
    const idx = matchQueue.indexOf(socket.id);
    if (idx > -1) matchQueue.splice(idx, 1);
    const player = connectedPlayers.get(socket.id);
    if (player) player.inQueue = false;
    socket.emit('queue_left');
  });

  // ── Join via invite code ─────────────────────────────────────────────────
  socket.on('join_invite', (code) => {
    const player = connectedPlayers.get(socket.id);
    if (!player?.itchId) { socket.emit('error', 'Not authenticated'); return; }

    const invite = inviteCodes.get(code);
    if (!invite)  { socket.emit('invite_error', 'Invite not found or expired'); return; }

    const age = Date.now() - invite.createdAt;
    if (age > 10 * 60 * 1000) {
      inviteCodes.delete(code);
      socket.emit('invite_error', 'Invite has expired');
      return;
    }

    // Find the host socket
    let hostSocketId = null;
    for (const [sid, p] of connectedPlayers) {
      if (p.itchId === invite.itchId) { hostSocketId = sid; break; }
    }

    if (!hostSocketId) { socket.emit('invite_error', 'Host is no longer online'); return; }

    inviteCodes.delete(code); // one-use invite
    createMatch(hostSocketId, socket.id, invite.roomId);
  });

  // ── Host waits in invite room ───────────────────────────────────────────────
  socket.on('host_invite_room', (code) => {
    const invite = inviteCodes.get(code);
    if (!invite) { socket.emit('invite_error', 'Invite not found'); return; }
    socket.join(invite.roomId); // host joins room and waits
    console.log(`[Socket] Host waiting in room ${invite.roomId}`);
  });

  // ── In-game events (relay between players) ──────────────────────────────
  socket.on('game_action', (data) => {
    const player = connectedPlayers.get(socket.id);
    if (!player?.roomId) return;
    // Relay to the other player in the room
    socket.to(player.roomId).emit('opponent_action', data);
  });

  // ── Disconnect ───────────────────────────────────────────────────────────
  socket.on('disconnect', () => {
    const player = connectedPlayers.get(socket.id);
    if (player) {
      // Remove from queue
      const idx = matchQueue.indexOf(socket.id);
      if (idx > -1) matchQueue.splice(idx, 1);

      // Notify opponent if in a room
      if (player.roomId) {
        socket.to(player.roomId).emit('opponent_disconnected');
        activeRooms.delete(player.roomId);
      }
    }
    connectedPlayers.delete(socket.id);
    io.emit('online_count', connectedPlayers.size);
    console.log(`[Socket] Disconnected: ${socket.id}`);
  });
});

// ── Match creation helpers ────────────────────────────────────────────────────
function tryMakeMatch() {
  if (matchQueue.length < 2) return;

  const socketIdA = matchQueue.shift();
  const socketIdB = matchQueue.shift();

  const playerA = connectedPlayers.get(socketIdA);
  const playerB = connectedPlayers.get(socketIdB);

  if (!playerA || !playerB) {
    // One disconnected — put the other back
    if (playerA) matchQueue.unshift(socketIdA);
    if (playerB) matchQueue.unshift(socketIdB);
    return;
  }

  const roomId = `room_${crypto.randomBytes(8).toString('hex')}`;
  createMatch(socketIdA, socketIdB, roomId);
}

function createMatch(socketIdA, socketIdB, roomId) {
  const playerA = connectedPlayers.get(socketIdA);
  const playerB = connectedPlayers.get(socketIdB);

  if (!playerA || !playerB) return;

  playerA.inQueue = false;
  playerB.inQueue = false;
  playerA.roomId  = roomId;
  playerB.roomId  = roomId;

  // Randomly decide who sees inside the box (the "peeker")
  const peekerIsA = Math.random() < 0.5;

  activeRooms.set(roomId, {
    players: [socketIdA, socketIdB],
    state:   'waiting'
  });

  // Join both to the Socket.io room
  const socketA = io.sockets.sockets.get(socketIdA);
  const socketB = io.sockets.sockets.get(socketIdB);
  socketA?.join(roomId);
  socketB?.join(roomId);

  // Notify both players — tell each their role
  socketA?.emit('match_found', {
    roomId,
    opponentName: playerB.displayName,
    role:         peekerIsA ? 'peeker' : 'guesser',  // peeker sees inside box
    message:      `Match found! Playing against ${playerB.displayName}`
  });

  socketB?.emit('match_found', {
    roomId,
    opponentName: playerA.displayName,
    role:         peekerIsA ? 'guesser' : 'peeker',
    message:      `Match found! Playing against ${playerA.displayName}`
  });

  console.log(`[Match] Created room ${roomId}: ${playerA.displayName} vs ${playerB.displayName}`);
}

// ── Start server ──────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log(`🥕 Carrot server running on port ${PORT}`));
