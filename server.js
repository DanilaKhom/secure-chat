const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const path = require('path');
const { createClient } = require('@libsql/client');
require('dotenv').config();

const cryptoModule = require('crypto');

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: { origin: '*', methods: ['GET', 'POST'] },
  transports: ['websocket', 'polling'],
  maxHttpBufferSize: 1e7
});

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

const userSockets = new Map(); // userId -> Set of socketIds

// ─── Database ────────────────────────────────────────────────────────────────
let db;
async function initDb() {
  db = createClient({
    url: process.env.TURSO_DATABASE_URL,
    authToken: process.env.TURSO_AUTH_TOKEN
  });

  await db.executeMultiple(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      publicKey TEXT NOT NULL,
      passwordHash TEXT,
      encryptedPrivKey TEXT
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
    CREATE TABLE IF NOT EXISTS friend_requests (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      senderId INTEGER NOT NULL,
      receiverId INTEGER NOT NULL,
      timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
      UNIQUE(senderId, receiverId)
    );
  `);
  
  try {
    await db.execute('ALTER TABLE users ADD COLUMN passwordHash TEXT');
  } catch (e) {}
  try {
    await db.execute('ALTER TABLE users ADD COLUMN encryptedPrivKey TEXT');
  } catch (e) {}
  console.log('DB ready');

  // Clean up messages older than 24 hours periodically (every 10 minutes)
  setInterval(async () => {
    try {
      await db.execute("DELETE FROM messages WHERE timestamp < DATETIME('now', '-24 hours')");
    } catch(e) {
      console.error('Auto cleanup error:', e);
    }
  }, 10 * 60 * 1000);
}

// Helper functions to mimic sqlite interface
async function dbGet(sql, args = []) {
  const result = await db.execute({ sql, args });
  return result.rows[0];
}

async function dbAll(sql, args = []) {
  const result = await db.execute({ sql, args });
  return result.rows;
}

async function dbRun(sql, args = []) {
  const result = await db.execute({ sql, args });
  return { lastID: Number(result.lastInsertRowid) };
}


// ─── REST API ─────────────────────────────────────────────────────────────────
app.post('/api/log', (req, res) => {
  console.log('CLIENT LOG:', req.body);
  res.json({ok:true});
});

app.post('/api/register', async (req, res) => {
  const { username, password, publicKey, encryptedPrivKey } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Заполните все поля (никнейм и пароль)' });

  const cleanUser = String(username).trim();
  const cleanPass = String(password).trim();
  if (!cleanUser || !cleanPass) return res.status(400).json({ error: 'Никнейм и пароль не могут быть пустыми' });

  const hash = cryptoModule.createHash('sha256').update(cleanPass).digest('hex');

  try {
    const existing = await dbGet('SELECT * FROM users WHERE LOWER(username) = LOWER(?)', [cleanUser]);
    if (existing) {
      if (existing.passwordHash && existing.passwordHash !== hash) {
        return res.status(401).json({ error: 'Неверный пароль для этого никнейма!' });
      }
      
      // Return existing user info so client can decrypt their private key
      return res.json({ 
        id: existing.id, 
        username: existing.username, 
        publicKey: existing.publicKey,
        encryptedPrivKey: existing.encryptedPrivKey
      });
    }

    if (!publicKey || !encryptedPrivKey) {
      return res.status(400).json({ error: 'Для регистрации нужны ключи шифрования' });
    }

    const result = await dbRun('INSERT INTO users (username, publicKey, passwordHash, encryptedPrivKey) VALUES (?, ?, ?, ?)', [cleanUser, publicKey, hash, encryptedPrivKey]);
    res.json({ id: result.lastID, username: cleanUser, publicKey, encryptedPrivKey });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/reset-account', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Укажите никнейм и пароль' });
  const cleanUser = String(username).trim();
  const cleanPass = String(password).trim();
  const hash = cryptoModule.createHash('sha256').update(cleanPass).digest('hex');
  
  try {
    const user = await dbGet('SELECT id, passwordHash FROM users WHERE LOWER(username) = LOWER(?)', [cleanUser]);
    if (user) {
      if (user.passwordHash && user.passwordHash !== hash) {
        return res.status(401).json({ error: 'Неверный пароль' });
      }
      await dbRun('DELETE FROM messages WHERE senderId = ? OR receiverId = ?', [user.id, user.id]);
      await dbRun('DELETE FROM friends WHERE userId = ? OR friendId = ?', [user.id, user.id]);
      await dbRun('DELETE FROM friend_requests WHERE senderId = ? OR receiverId = ?', [user.id, user.id]);
      await dbRun('DELETE FROM users WHERE id = ?', [user.id]);
    }
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/wipe-db', async (req, res) => {
  try {
    await dbRun('DELETE FROM messages');
    await dbRun('DELETE FROM friends');
    await dbRun('DELETE FROM friend_requests');
    await dbRun('DELETE FROM users');
    res.json({ success: true, message: 'Database wiped' });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Friends API
app.post('/api/friends/request', async (req, res) => {
  const { senderId, receiverId } = req.body;
  if (!senderId || !receiverId) return res.status(400).json({ error: 'Missing fields' });
  try {
    const existing = await dbGet('SELECT id FROM friends WHERE userId = ? AND friendId = ?', [senderId, receiverId]);
    if (existing) return res.status(400).json({ error: 'Already friends' });

    // Check if the other user already sent a request to us
    const reverseReq = await dbGet('SELECT id FROM friend_requests WHERE senderId = ? AND receiverId = ?', [receiverId, senderId]);
    if (reverseReq) {
      // Auto-accept!
      await dbRun('DELETE FROM friend_requests WHERE senderId = ? AND receiverId = ?', [receiverId, senderId]);
      await dbRun('INSERT OR IGNORE INTO friends (userId, friendId) VALUES (?, ?)', [senderId, receiverId]);
      await dbRun('INSERT OR IGNORE INTO friends (userId, friendId) VALUES (?, ?)', [receiverId, senderId]);

      const receiver = await dbGet('SELECT username FROM users WHERE id = ?', [receiverId]);
      const sSockets = userSockets.get(String(senderId));
      if (sSockets) {
        for (const sid of sSockets) io.to(sid).emit('friend_accepted', { accepterId: senderId, accepterName: receiver.username });
      }
      return res.json({ success: true, accepted: true });
    }

    await dbRun('INSERT OR IGNORE INTO friend_requests (senderId, receiverId) VALUES (?, ?)', [senderId, receiverId]);

    const sender = await dbGet('SELECT username FROM users WHERE id = ?', [senderId]);
    const rSockets = userSockets.get(String(receiverId));
    if (rSockets) {
      for (const sid of rSockets) io.to(sid).emit('friend_request', { senderId, senderName: sender.username });
    }

    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/friends/accept', async (req, res) => {
  const { senderId, receiverId } = req.body;
  if (!senderId || !receiverId) return res.status(400).json({ error: 'Missing fields' });
  try {
    await dbRun('DELETE FROM friend_requests WHERE senderId = ? AND receiverId = ?', [senderId, receiverId]);
    await dbRun('INSERT OR IGNORE INTO friends (userId, friendId) VALUES (?, ?)', [senderId, receiverId]);
    await dbRun('INSERT OR IGNORE INTO friends (userId, friendId) VALUES (?, ?)', [receiverId, senderId]);

    const receiver = await dbGet('SELECT username FROM users WHERE id = ?', [receiverId]);
    const sSockets = userSockets.get(String(senderId));
    if (sSockets) {
      for (const sid of sSockets) io.to(sid).emit('friend_accepted', { accepterId: receiverId, accepterName: receiver.username });
    }

    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/friends/reject', async (req, res) => {
  const { senderId, receiverId } = req.body;
  if (!senderId || !receiverId) return res.status(400).json({ error: 'Missing fields' });
  try {
    await dbRun('DELETE FROM friend_requests WHERE senderId = ? AND receiverId = ?', [senderId, receiverId]);
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/friends/remove', async (req, res) => {
  const { userId, friendId } = req.body;
  if (!userId || !friendId) return res.status(400).json({ error: 'Missing fields' });
  try {
    await dbRun('DELETE FROM friends WHERE (userId = ? AND friendId = ?) OR (userId = ? AND friendId = ?)', [userId, friendId, friendId, userId]);
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/friends/:userId', async (req, res) => {
  const { userId } = req.params;
  try {
    const friends = await dbAll(`
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

app.get('/api/friends/requests/:userId', async (req, res) => {
  const { userId } = req.params;
  try {
    const requests = await dbAll(`
      SELECT u.id, u.username, u.publicKey
      FROM users u
      JOIN friend_requests fr ON u.id = fr.senderId
      WHERE fr.receiverId = ?
    `, [userId]);
    res.json(requests);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/users/search', async (req, res) => {
  const { query } = req.query;
  try {
    const allUsers = await dbAll('SELECT id, username, publicKey FROM users');
    if (!query || !query.trim()) {
      return res.json(allUsers.slice(0, 20));
    }
    const cleanQ = query.trim().toLowerCase();
    const matched = allUsers.filter(u => u.username && u.username.toLowerCase().includes(cleanQ)).slice(0, 20);
    res.json(matched);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/users/:id', async (req, res) => {
  const user = await dbGet('SELECT id, username, publicKey FROM users WHERE id = ?', [req.params.id]);
  if (user) res.json(user); else res.status(404).json({ error: 'Not found' });
});

app.get('/api/messages/:userId/:friendId', async (req, res) => {
  const { userId, friendId } = req.params;
  const messages = await dbAll(`
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
  const chats = await dbAll(`
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
      const result = await dbRun(
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
}).catch(console.error);
