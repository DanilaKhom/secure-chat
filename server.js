const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const path = require('path');
const sqlite3 = require('sqlite3').verbose();
const { open } = require('sqlite');

const cryptoModule = require('crypto');

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: { origin: '*', methods: ['GET', 'POST'] },
  transports: ['websocket', 'polling']
});

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ─── Database ────────────────────────────────────────────────────────────────
let db;
async function initDb() {
  db = await open({ filename: path.join(__dirname, 'chat.sqlite'), driver: sqlite3.Database });
  await db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      publicKey TEXT NOT NULL,
      passwordHash TEXT
    );
    CREATE TABLE IF NOT EXISTS messages (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      senderId INTEGER NOT NULL,
      receiverId INTEGER NOT NULL,
      encryptedContent TEXT NOT NULL,
      senderCopy TEXT,
      timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS friends (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      userId INTEGER NOT NULL,
      friendId INTEGER NOT NULL,
      UNIQUE(userId, friendId)
    );
  `);
  try {
    await db.exec('ALTER TABLE users ADD COLUMN passwordHash TEXT');
  } catch (e) {}
  console.log('DB ready');

  // Clean up messages older than 24 hours periodically (every 10 minutes)
  setInterval(async () => {
    try {
      await db.run("DELETE FROM messages WHERE timestamp < DATETIME('now', '-24 hours')");
    } catch(e) {
      console.error('Auto cleanup error:', e);
    }
  }, 10 * 60 * 1000);
}

// ─── REST API ─────────────────────────────────────────────────────────────────
app.post('/api/register', async (req, res) => {
  const { username, password, publicKey } = req.body;
  if (!username || !publicKey || !password) return res.status(400).json({ error: 'Заполните все поля (никнейм и пароль)' });

  const hash = cryptoModule.createHash('sha256').update(password).digest('hex');

  try {
    const existing = await db.get('SELECT * FROM users WHERE username = ?', [username]);
    if (existing) {
      if (existing.passwordHash && existing.passwordHash !== hash) {
        return res.status(401).json({ error: 'Неверный пароль для этого никнейма!' });
      }
      await db.run('UPDATE users SET publicKey = ?, passwordHash = ? WHERE username = ?', [publicKey, hash, username]);
      const user = await db.get('SELECT id, username, publicKey FROM users WHERE username = ?', [username]);
      return res.json(user);
    }

    const result = await db.run('INSERT INTO users (username, publicKey, passwordHash) VALUES (?, ?, ?)', [username, publicKey, hash]);
    res.json({ id: result.lastID, username, publicKey });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Friends API
app.post('/api/friends/add', async (req, res) => {
  const { userId, friendId } = req.body;
  if (!userId || !friendId) return res.status(400).json({ error: 'Missing fields' });
  try {
    await db.run('INSERT OR IGNORE INTO friends (userId, friendId) VALUES (?, ?)', [userId, friendId]);
    await db.run('INSERT OR IGNORE INTO friends (userId, friendId) VALUES (?, ?)', [friendId, userId]);
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/friends/remove', async (req, res) => {
  const { userId, friendId } = req.body;
  if (!userId || !friendId) return res.status(400).json({ error: 'Missing fields' });
  try {
    await db.run('DELETE FROM friends WHERE (userId = ? AND friendId = ?) OR (userId = ? AND friendId = ?)', [userId, friendId, friendId, userId]);
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/friends/:userId', async (req, res) => {
  const { userId } = req.params;
  try {
    const friends = await db.all(`
      SELECT u.id, u.username, u.publicKey
      FROM users u
      JOIN friends f ON u.id = f.friendId
      WHERE f.userId = ?
    `, [userId]);
    res.json(friends);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/users/search', async (req, res) => {
  const { query } = req.query;
  if (!query) return res.json([]);
  const users = await db.all('SELECT id, username, publicKey FROM users WHERE username LIKE ? LIMIT 10', [`%${query}%`]);
  res.json(users);
});

app.get('/api/users/:id', async (req, res) => {
  const user = await db.get('SELECT id, username, publicKey FROM users WHERE id = ?', [req.params.id]);
  if (user) res.json(user); else res.status(404).json({ error: 'Not found' });
});

app.get('/api/messages/:userId/:friendId', async (req, res) => {
  const { userId, friendId } = req.params;
  const messages = await db.all(`
    SELECT id, senderId, receiverId,
      CASE WHEN senderId = ? THEN senderCopy ELSE encryptedContent END as encryptedContent,
      timestamp
    FROM messages
    WHERE ((senderId = ? AND receiverId = ?) OR (senderId = ? AND receiverId = ?))
      AND timestamp >= DATETIME('now', '-24 hours')
    ORDER BY timestamp ASC
  `, [userId, userId, friendId, friendId, userId]);
  res.json(messages);
});

app.get('/api/chats/:userId', async (req, res) => {
  const { userId } = req.params;
  const chats = await db.all(`
    SELECT DISTINCT u.id, u.username, u.publicKey
    FROM users u
    JOIN messages m ON (u.id = m.senderId OR u.id = m.receiverId)
    WHERE (m.senderId = ? OR m.receiverId = ?)
      AND u.id != ?
      AND m.timestamp >= DATETIME('now', '-24 hours')
  `, [userId, userId, userId]);
  res.json(chats);
});

// ─── Socket.IO ────────────────────────────────────────────────────────────────
const userSockets = new Map(); // userId -> Set of socketIds

io.on('connection', (socket) => {
  console.log('Connected:', socket.id);

  socket.on('register', (userId) => {
    const uid = String(userId);
    if (!userSockets.has(uid)) userSockets.set(uid, new Set());
    userSockets.get(uid).add(socket.id);
    socket.data.userId = uid;
    console.log(`User ${uid} registered (socket ${socket.id}). Online: ${[...userSockets.keys()]}`);
  });

  socket.on('private_message', async (data) => {
    const { senderId, receiverId, encryptedContent, senderCopy } = data;
    console.log(`MSG from ${senderId} to ${receiverId}`);

    // Save to DB
    try {
      const result = await db.run(
        'INSERT INTO messages (senderId, receiverId, encryptedContent, senderCopy) VALUES (?, ?, ?, ?)',
        [senderId, receiverId, encryptedContent, senderCopy || null]
      );

      const message = {
        id: result.lastID,
        senderId,
        receiverId,
        encryptedContent,
        timestamp: new Date().toISOString()
      };

      // Deliver to ALL receiver's sockets
      const receiverSockets = userSockets.get(String(receiverId));
      if (receiverSockets && receiverSockets.size > 0) {
        console.log(`Delivering to ${receiverSockets.size} socket(s) of user ${receiverId}`);
        for (const sid of receiverSockets) {
          io.to(sid).emit('private_message', message);
        }
      } else {
        console.log(`User ${receiverId} is offline — message saved to DB`);
      }

      // Confirm to sender
      socket.emit('message_sent', { ...message, encryptedContent: senderCopy || encryptedContent });
    } catch (e) {
      console.error('Error saving message:', e);
      socket.emit('error', { message: 'Failed to send' });
    }
  });

  socket.on('disconnect', () => {
    const uid = socket.data.userId;
    if (uid && userSockets.has(uid)) {
      userSockets.get(uid).delete(socket.id);
      if (userSockets.get(uid).size === 0) userSockets.delete(uid);
    }
    console.log('Disconnected:', socket.id);
  });
});

// Catch-all: serve index.html
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

initDb().then(() => {
  const PORT = process.env.PORT || 3000;
  server.listen(PORT, '0.0.0.0', () => {
    console.log(`\n🚀 Chat server running on http://0.0.0.0:${PORT}\n`);
  });
});
