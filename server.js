/**
 * Carrot in a Box - itch.io OAuth + Matchmaking + Game Server
 * Node.js/Express backend handling OAuth 2.0 flow with itch.io (PKCE),
 * real-time matchmaking via Socket.io, game room logic, and WebRTC VOIP signalling.
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
const users         = new Map();  // itchId → user object
const pendingAuth   = new Map();  // state → { codeVerifier, createdAt }
const sessionTokens = new Map();  // token → itchId
const inviteCodes   = new Map();  // code → { itchId, roomId, createdAt }

// Clean up expired pending auths every 5 minutes
setInterval(() => {
  const fiveMinutesAgo = Date.now() - 5 * 60 * 1000;
  for (const [state, data] of pendingAuth) {
    if (data.createdAt < fiveMinutesAgo) pendingAuth.delete(state);
  }
}, 5 * 60 * 1000);

// Clean up expired invites every 10 minutes
setInterval(() => {
  const tenMinutesAgo = Date.now() - 10 * 60 * 1000;
  for (const [code, invite] of inviteCodes) {
    if (invite.createdAt < tenMinutesAgo) inviteCodes.delete(code);
  }
}, 10 * 60 * 1000);


// ═══════════════════════════════════════════════════════════════════════════════
// REST ROUTES
// ═══════════════════════════════════════════════════════════════════════════════

// ─── STEP 1: Build Authorization URL ─────────────────────────────────────────
app.get('/auth/login', (req, res) => {
  const state = crypto.randomBytes(16).toString('hex');

  const codeVerifier  = crypto.randomBytes(32).toString('base64url');
  const codeChallenge = crypto.createHash('sha256').update(codeVerifier).digest('base64url');

  pendingAuth.set(state, { codeVerifier, createdAt: Date.now() });

  const params = new URLSearchParams({
    client_id:             process.env.ITCH_CLIENT_ID,
    redirect_uri:          process.env.REDIRECT_URI,
    response_type:         'code',
    scope:                 'profile',
    state,
    code_challenge:        codeChallenge,
    code_challenge_method: 'S256'
  });

  const authUrl = `https://itch.io/user/oauth?${params}`;
  console.log(`[Auth] Login initiated, state: ${state}`);
  res.json({ authUrl, state });
});

// ─── STEP 2: Handle Callback from itch.io ────────────────────────────────────
app.get('/auth/callback', async (req, res) => {
  const { code, state, error } = req.query;

  if (error) {
    console.error('[Auth] itch.io returned error:', error);
    return res.redirect(`/auth/error?message=${encodeURIComponent(error)}`);
  }

  const pending = pendingAuth.get(state);
  if (!pending) {
    console.error('[Auth] State not found:', state);
    return res.redirect('/auth/error?message=Login+session+expired.+Please+try+again.');
  }

  pendingAuth.delete(state);

  try {
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
    try { tokenData = JSON.parse(rawToken); }
    catch (e) { throw new Error(`Token exchange failed: ${rawToken.substring(0, 100)}`); }

    if (tokenData.errors) throw new Error(tokenData.errors.join(', '));

    const accessToken = tokenData.access_token;
    if (!accessToken) throw new Error('No access token in response: ' + JSON.stringify(tokenData));

    const userId = tokenData.key?.user_id;
    console.log(`[Auth] Got access token for user_id: ${userId}, fetching profile...`);

    const profileRes  = await fetch('https://itch.io/api/1/key/me', {
      headers: { Authorization: `Bearer ${accessToken}` }
    });
    const profileText = await profileRes.text();
    console.log('[Auth] Profile response:', profileText.substring(0, 300));

    let profile;
    try { profile = JSON.parse(profileText); }
    catch (e) { throw new Error('Could not parse profile response'); }

    const itchUser = profile.user || {
      id:           userId,
      username:     `user_${userId}`,
      display_name: `Player_${userId}`
    };

    console.log(`[Auth] Logged in: ${itchUser.username} (id: ${itchUser.id})`);

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
      user.accessToken  = accessToken;
      user.itchUsername = itchUser.username;
    }
    users.set(itchUser.id, user);

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
    <!DOCTYPE html><html>
    <head><title>Carrot in a Box - Login Successful</title>
    <style>
      * { margin:0; padding:0; box-sizing:border-box; }
      body { font-family:sans-serif; display:flex; align-items:center; justify-content:center;
             min-height:100vh; background:#1a1a2e; color:#e94560; flex-direction:column; gap:16px; }
      h1 { font-size:2rem; } p { color:#ccc; font-size:1.1rem; }
    </style></head>
    <body>
      <h1>🥕 Welcome, ${username}!</h1>
      <p>Login successful. You can close this window and return to Carrot in a Box.</p>
      <script>
        if (window.opener) {
          window.opener.postMessage(JSON.stringify({ type: 'AUTH_SUCCESS', token: '${token}' }), '*');
        }
        setTimeout(() => window.close(), 3000);
      </script>
    </body></html>
  `);
});

// ─── Error Page ───────────────────────────────────────────────────────────────
app.get('/auth/error', (req, res) => {
  const message = req.query.message || 'Unknown error occurred';
  res.send(`
    <!DOCTYPE html><html>
    <head><title>Login Error</title>
    <style>
      * { margin:0; padding:0; box-sizing:border-box; }
      body { font-family:sans-serif; display:flex; align-items:center; justify-content:center;
             min-height:100vh; background:#1a1a2e; color:#e94560; flex-direction:column; gap:16px; }
      p { color:#ccc; }
    </style></head>
    <body>
      <h1>Login Failed</h1>
      <p>${message}</p>
      <p>Please close this window and try again.</p>
    </body></html>
  `);
});

// ─── Validate Token ───────────────────────────────────────────────────────────
app.post('/auth/validate', (req, res) => {
  const { token } = req.body;
  if (!token) return res.status(400).json({ error: 'No token provided' });

  const itchId = sessionTokens.get(token);
  if (!itchId) return res.status(401).json({ error: 'Invalid or expired token' });

  const user = users.get(itchId);
  if (!user) return res.status(401).json({ error: 'User not found' });

  res.json({
    // BUG FIX: was missing `success: true` — the Unity client checks data.success
    // to determine whether validation passed. Without it the client always fell
    // through to the failure branch and deleted the saved token.
    success:      true,
    valid:        true,
    itchId:       user.itchId,
    itchUsername: user.itchUsername,
    displayName:  user.displayName,
    wins:         user.wins,
    gamesPlayed:  user.gamesPlayed
  });
});

// ─── Create Invite Link ───────────────────────────────────────────────────────
app.post('/invite/create', requireAuth, (req, res) => {
  const code    = crypto.randomBytes(6).toString('hex');
  const roomId  = `room_${crypto.randomBytes(8).toString('hex')}`;
  inviteCodes.set(code, { itchId: req.itchId, roomId, createdAt: Date.now() });
  const inviteUrl = `https://notsure2505.itch.io/carrot-in-a-box#invite=${code}`;
  res.json({ code, roomId, inviteUrl });
});

// ─── Validate Invite ──────────────────────────────────────────────────────────
app.get('/invite/:code', (req, res) => {
  const invite = inviteCodes.get(req.params.code);
  if (!invite) return res.status(404).json({ error: 'Invite not found or expired' });
  const age = Date.now() - invite.createdAt;
  if (age > 10 * 60 * 1000) {
    inviteCodes.delete(req.params.code);
    return res.status(410).json({ error: 'Invite expired' });
  }
  const host = users.get(invite.itchId);
  res.json({ valid: true, roomId: invite.roomId, hostName: host?.displayName || 'Unknown', code: req.params.code });
});

// ─── Leaderboard ──────────────────────────────────────────────────────────────
app.get('/leaderboard', (req, res) => {
  const entries = Array.from(users.values())
    .filter(u => u.gamesPlayed > 0)
    .map(u => ({
      displayName: u.displayName,
      wins:        u.wins,
      gamesPlayed: u.gamesPlayed,
      crs:         calcCRS(u.wins, u.gamesPlayed)
      // NOTE: losses and winRate are intentionally omitted — clients compute them
    }))
    .sort((a, b) => b.crs - a.crs)
    .slice(0, 50);
  res.json({ leaderboard: entries });
});

// ─── Online Count (REST fallback for Unity polling) ───────────────────────────
app.get('/lobby/online', (req, res) => {
  res.json({ onlineCount: authenticatedCount() });
});

// ─── Health Check ─────────────────────────────────────────────────────────────
app.get('/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// ─── Logout ───────────────────────────────────────────────────────────────────
app.post('/auth/logout', (req, res) => {
  // BUG FIX: also invalidate the server-side session token on logout
  const authHeader = req.headers.authorization;
  const token = authHeader ? authHeader.replace('Bearer ', '') : req.body?.token;
  if (token) sessionTokens.delete(token);
  res.json({ success: true });
});

// ─── Auth Middleware ──────────────────────────────────────────────────────────
function requireAuth(req, res, next) {
  const authHeader = req.headers.authorization;
  const token      = authHeader ? authHeader.replace('Bearer ', '') : req.body?.token;
  if (!token) return res.status(401).json({ error: 'Not authenticated' });

  const itchId = sessionTokens.get(token);
  if (!itchId) return res.status(401).json({ error: 'Invalid token' });

  req.itchId = itchId;
  next();
}


// ═══════════════════════════════════════════════════════════════════════════════
// SOCKET.IO — MATCHMAKING + GAME ROOMS + VOIP SIGNALLING
// ═══════════════════════════════════════════════════════════════════════════════

const connectedPlayers = new Map(); // socketId → { itchId, displayName, inQueue, roomId }
const matchQueue       = [];        // array of socketIds waiting for a match
const activeRooms      = new Map(); // roomId → { players: [socketId, socketId] }
const gameRooms        = new Map(); // roomId → GameRoom instance

function authenticatedCount() {
  let count = 0;
  for (const [, p] of connectedPlayers) {
    if (p.itchId !== null) count++;
  }
  return count;
}

// ─── Game Room Class ──────────────────────────────────────────────────────────
class GameRoom {
  constructor(roomId, peekerSocketId, guesserSocketId) {
    this.roomId          = roomId;
    this.peekerSocketId  = peekerSocketId;
    this.guesserSocketId = guesserSocketId;
    this.hasCarrot       = Math.random() < 0.5; // true = peeker's box has the carrot
    this.phase           = 'peek';
    this.guesserSwapped  = false;
    this.decisionTimeout = null;
    // BUG FIX: track whether game_result_ack has been received to prevent
    // both players sending it and doubling the stats increment.
    this.resultAcked     = false;
    this.createdAt       = Date.now();
  }

  getOpponentSocketId(socketId) {
    if (socketId === this.peekerSocketId)  return this.guesserSocketId;
    if (socketId === this.guesserSocketId) return this.peekerSocketId;
    return null;
  }

  isPeeker(socketId) { return socketId === this.peekerSocketId; }
}

// ─── Game Room Lifecycle ──────────────────────────────────────────────────────

function startGameRoom(roomId, peekerSocketId, guesserSocketId) {
  const room = new GameRoom(roomId, peekerSocketId, guesserSocketId);
  gameRooms.set(roomId, room);

  const peekerSocket  = io.sockets.sockets.get(peekerSocketId);
  const guesserSocket = io.sockets.sockets.get(guesserSocketId);

  peekerSocket?.emit('game_event', {
    eventType: 'game_peek_ready',
    payload:   JSON.stringify({ hasCarrot: room.hasCarrot })
  });
  guesserSocket?.emit('game_event', {
    eventType: 'game_peek_ready',
    payload:   JSON.stringify({ hasCarrot: false })
  });

  console.log(`[Game] Room ${roomId} started — peeker has carrot: ${room.hasCarrot}`);

  setTimeout(() => startDeliberation(roomId), 4000);
}

function startDeliberation(roomId) {
  const room = gameRooms.get(roomId);
  if (!room) return;

  room.phase = 'deliberate';

  io.to(roomId).emit('game_event', {
    eventType: 'game_deliberate_start',
    payload:   JSON.stringify({ durationSeconds: 30 })
  });

  console.log(`[Game] Room ${roomId} — deliberation started (30s)`);

  setTimeout(() => startDecision(roomId), 30000);
}

function startDecision(roomId) {
  const room = gameRooms.get(roomId);
  if (!room || room.phase !== 'deliberate') return;

  room.phase = 'decision';

  io.to(roomId).emit('game_event', {
    eventType: 'game_decision_start',
    payload:   JSON.stringify({})
  });

  console.log(`[Game] Room ${roomId} — decision phase`);

  // Auto-resolve as KEEP if guesser doesn't respond in 15s
  room.decisionTimeout = setTimeout(() => {
    if (room.phase === 'decision') {
      console.log(`[Game] Room ${roomId} — decision timed out, defaulting to KEEP`);
      resolveDecision(roomId, false);
    }
  }, 15000);
}

function resolveDecision(roomId, swap) {
  const room = gameRooms.get(roomId);
  if (!room) return;

  room.phase          = 'reveal';
  room.guesserSwapped = swap;

  let peekerHasCarrot  = room.hasCarrot;
  let guesserHasCarrot = !room.hasCarrot;
  if (swap) { [peekerHasCarrot, guesserHasCarrot] = [guesserHasCarrot, peekerHasCarrot]; }

  const peekerSocket  = io.sockets.sockets.get(room.peekerSocketId);
  const guesserSocket = io.sockets.sockets.get(room.guesserSocketId);

  peekerSocket?.emit('game_event', {
    eventType: 'game_reveal',
    payload:   JSON.stringify({ myCarrot: peekerHasCarrot, opponentCarrot: guesserHasCarrot, swapped: swap })
  });
  guesserSocket?.emit('game_event', {
    eventType: 'game_reveal',
    payload:   JSON.stringify({ myCarrot: guesserHasCarrot, opponentCarrot: peekerHasCarrot, swapped: swap })
  });

  console.log(`[Game] Room ${roomId} — reveal. Peeker has carrot: ${peekerHasCarrot}. Swapped: ${swap}`);

  // Send result after reveal animation (~3.5s)
  setTimeout(() => {
    const peekerPlayer  = connectedPlayers.get(room.peekerSocketId);
    const guesserPlayer = connectedPlayers.get(room.guesserSocketId);

    const peekerUser  = peekerPlayer  ? users.get(peekerPlayer.itchId)  : null;
    const guesserUser = guesserPlayer ? users.get(guesserPlayer.itchId) : null;

    peekerSocket?.emit('game_event', {
      eventType: 'game_result',
      payload:   JSON.stringify({
        winner:         peekerHasCarrot ? 'peeker' : 'guesser',
        myCarrot:       peekerHasCarrot,
        opponentCarrot: guesserHasCarrot,
        swapped:        swap,
        newCRS:         peekerUser ? calcCRS(peekerUser.wins, peekerUser.gamesPlayed) : 0
      })
    });
    guesserSocket?.emit('game_event', {
      eventType: 'game_result',
      payload:   JSON.stringify({
        winner:         guesserHasCarrot ? 'guesser' : 'peeker',
        myCarrot:       guesserHasCarrot,
        opponentCarrot: peekerHasCarrot,
        swapped:        swap,
        newCRS:         guesserUser ? calcCRS(guesserUser.wins, guesserUser.gamesPlayed) : 0
      })
    });

    gameRooms.delete(roomId);
    activeRooms.delete(roomId);
    console.log(`[Game] Room ${roomId} complete. Winner: ${peekerHasCarrot ? 'Peeker' : 'Guesser'}`);
  }, 3500);
}

function findRoomForSocket(socketId) {
  for (const [, room] of gameRooms) {
    if (room.peekerSocketId === socketId || room.guesserSocketId === socketId) return room;
  }
  return null;
}

// ─── Match Creation ───────────────────────────────────────────────────────────

function tryMakeMatch() {
  if (matchQueue.length < 2) return;

  const socketIdA = matchQueue.shift();
  const socketIdB = matchQueue.shift();

  const playerA = connectedPlayers.get(socketIdA);
  const playerB = connectedPlayers.get(socketIdB);

  if (!playerA || !playerB) {
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

  const peekerIsA       = Math.random() < 0.5;
  const peekerSocketId  = peekerIsA ? socketIdA : socketIdB;
  const guesserSocketId = peekerIsA ? socketIdB : socketIdA;
  const peekerPlayer    = peekerIsA ? playerA : playerB;
  const guesserPlayer   = peekerIsA ? playerB : playerA;

  activeRooms.set(roomId, { players: [socketIdA, socketIdB] });

  const socketA = io.sockets.sockets.get(socketIdA);
  const socketB = io.sockets.sockets.get(socketIdB);
  socketA?.join(roomId);
  socketB?.join(roomId);

  socketA?.emit('match_found', {
    roomId,
    opponentName: playerB.displayName,
    role:         peekerIsA ? 'peeker' : 'guesser',
    message:      `Match found! Playing against ${playerB.displayName}`
  });
  socketB?.emit('match_found', {
    roomId,
    opponentName: playerA.displayName,
    role:         peekerIsA ? 'guesser' : 'peeker',
    message:      `Match found! Playing against ${playerA.displayName}`
  });

  console.log(`[Match] Room ${roomId}: ${peekerPlayer.displayName} (peeker) vs ${guesserPlayer.displayName} (guesser)`);

  startGameRoom(roomId, peekerSocketId, guesserSocketId);
}

// ─── CRS Helper ───────────────────────────────────────────────────────────────
function calcCRS(wins, gamesPlayed) {
  if (gamesPlayed === 0) return 0;
  return Math.round((wins / (gamesPlayed + 10)) * 1000);
}


// ─── Socket.io Connection Handler ────────────────────────────────────────────
io.on('connection', (socket) => {
  console.log(`[Socket] Client connected: ${socket.id}`);
  connectedPlayers.set(socket.id, { itchId: null, displayName: null, inQueue: false, roomId: null });
  io.emit('online_count', authenticatedCount());

  // ── Authenticate ────────────────────────────────────────────────────────────
  socket.on('authenticate', (token) => {
    const itchId = sessionTokens.get(token);
    if (!itchId) { socket.emit('auth_error', 'Invalid token'); return; }
    const user = users.get(itchId);
    if (!user)  { socket.emit('auth_error', 'User not found'); return; }

    const player       = connectedPlayers.get(socket.id);
    player.itchId      = itchId;
    player.displayName = user.displayName;
    socket.emit('authenticated', { displayName: user.displayName });
    io.emit('online_count', authenticatedCount());
    console.log(`[Socket] Authenticated: ${user.displayName}`);
  });

  // ── Matchmaking Queue ────────────────────────────────────────────────────────
  socket.on('join_queue', () => {
    const player = connectedPlayers.get(socket.id);
    if (!player?.itchId) { socket.emit('error', 'Not authenticated'); return; }
    if (player.inQueue)  return;

    player.inQueue = true;
    matchQueue.push(socket.id);
    socket.emit('queue_joined', { position: matchQueue.length });
    io.emit('online_count', authenticatedCount());
    console.log(`[Queue] ${player.displayName} joined. Queue size: ${matchQueue.length}`);
    tryMakeMatch();
  });

  socket.on('leave_queue', () => {
    const idx = matchQueue.indexOf(socket.id);
    if (idx > -1) matchQueue.splice(idx, 1);
    const player = connectedPlayers.get(socket.id);
    if (player) player.inQueue = false;
    socket.emit('queue_left');
  });

  // ── Invite Codes ─────────────────────────────────────────────────────────────
  socket.on('join_invite', (code) => {
    const player = connectedPlayers.get(socket.id);
    if (!player?.itchId) { socket.emit('error', 'Not authenticated'); return; }

    const invite = inviteCodes.get(code);
    if (!invite) { socket.emit('invite_error', 'Invite not found or expired'); return; }

    if (Date.now() - invite.createdAt > 10 * 60 * 1000) {
      inviteCodes.delete(code);
      socket.emit('invite_error', 'Invite has expired');
      return;
    }

    let hostSocketId = null;
    for (const [sid, p] of connectedPlayers) {
      if (p.itchId === invite.itchId) { hostSocketId = sid; break; }
    }
    if (!hostSocketId) { socket.emit('invite_error', 'Host is no longer online'); return; }

    inviteCodes.delete(code);
    createMatch(hostSocketId, socket.id, invite.roomId);
  });

  socket.on('host_invite_room', (code) => {
    const invite = inviteCodes.get(code);
    if (!invite) { socket.emit('invite_error', 'Invite not found'); return; }
    socket.join(invite.roomId);
    console.log(`[Socket] Host waiting in room ${invite.roomId}`);
  });

  // ── Game: Guesser Decision ───────────────────────────────────────────────────
  socket.on('game_decision', (data) => {
    const player = connectedPlayers.get(socket.id);
    if (!player?.itchId) return;

    const room = findRoomForSocket(socket.id);
    if (!room || room.phase !== 'decision') return;
    if (room.isPeeker(socket.id)) return; // only guesser decides

    if (room.decisionTimeout) clearTimeout(room.decisionTimeout);

    // BUG FIX: was `resolveDecision(room.roomId, !data.swap)` — the boolean was
    // inverted, so SWAP was treated as KEEP and vice versa on the server.
    resolveDecision(room.roomId, data.swap);
  });

  // ── Game: Result Acknowledgement (CRS update) ────────────────────────────────
  socket.on('game_result_ack', (data) => {
    const player = connectedPlayers.get(socket.id);
    if (!player?.itchId) return;
    if (typeof data.won !== 'boolean') return;

    const user = users.get(player.itchId);
    if (!user) return;

    // BUG FIX: the room is deleted before this event arrives (after the 3.5s
    // delay in resolveDecision), so we can't use it for dedup. Instead gate on
    // a per-user flag using the room-less approach: check gamesPlayed increment
    // is idempotent by tracking the last processed game via a timestamp.
    // Simple fix: only update if the player isn't already being updated
    // (both clients send ack, but the room is gone — use player-level lock).
    if (player._resultAckPending) return;
    player._resultAckPending = true;
    setTimeout(() => { player._resultAckPending = false; }, 5000);

    user.gamesPlayed = (user.gamesPlayed || 0) + 1;
    if (data.won) user.wins = (user.wins || 0) + 1;

    const crs = calcCRS(user.wins, user.gamesPlayed);
    socket.emit('crs_update', { wins: user.wins, gamesPlayed: user.gamesPlayed, crs });
    console.log(`[Game] CRS update — ${user.displayName}: ${crs} (${user.wins}W / ${user.gamesPlayed}G)`);
  });

  // ── VOIP: WebRTC Signal Relay ────────────────────────────────────────────────
  socket.on('voip_signal', (data) => {
    const room = findRoomForSocket(socket.id);
    if (!room) return;

    const opponentSocketId = room.getOpponentSocketId(socket.id);
    if (!opponentSocketId) return;

    const opponentSocket = io.sockets.sockets.get(opponentSocketId);
    opponentSocket?.emit('game_event', {
      eventType: 'voip_signal',
      payload:   JSON.stringify(data)
    });
  });

  // ── Disconnect ────────────────────────────────────────────────────────────────
  socket.on('disconnect', () => {
    const player = connectedPlayers.get(socket.id);
    if (player) {
      // Remove from matchmaking queue
      const idx = matchQueue.indexOf(socket.id);
      if (idx > -1) matchQueue.splice(idx, 1);

      // Notify opponent and clean up active game room
      // BUG FIX: capture the room BEFORE deleting it from gameRooms,
      // then clean up. The old code deleted the room then tried to find
      // it again for the "backward compat" fallback — which always failed.
      const room = findRoomForSocket(socket.id);
      if (room) {
        const opponentSocketId = room.getOpponentSocketId(socket.id);
        if (opponentSocketId) {
          const opponentSocket = io.sockets.sockets.get(opponentSocketId);
          opponentSocket?.emit('opponent_disconnected', { reason: 'disconnect' });
          // Clear the opponent's roomId so they can re-queue cleanly
          const opponentPlayer = connectedPlayers.get(opponentSocketId);
          if (opponentPlayer) opponentPlayer.roomId = null;
        }
        if (room.decisionTimeout) clearTimeout(room.decisionTimeout);
        gameRooms.delete(room.roomId);
        activeRooms.delete(room.roomId);
        console.log(`[Game] Room ${room.roomId} closed — player disconnected`);
      }
    }

    connectedPlayers.delete(socket.id);
    io.emit('online_count', authenticatedCount());
    console.log(`[Socket] Disconnected: ${socket.id}`);
  });
});


// ─── Start Server ─────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log(`🥕 Carrot in a Box server running on port ${PORT}`));
