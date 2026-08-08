const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const path = require('path');
const { createClient } = require('@libsql/client');
const webpush = require('web-push');
require('dotenv').config();

const cryptoModule = require('crypto');

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: { origin: '*', methods: ['GET', 'POST'] },
  transports: ['websocket', 'polling'],
  maxHttpBufferSize: 1e7
});

// VAPID keys setup
const publicVapidKey = process.env.VAPID_PUBLIC_KEY;
const privateVapidKey = process.env.VAPID_PRIVATE_KEY;
if (publicVapidKey && privateVapidKey) {
  webpush.setVapidDetails('mailto:test@test.com', publicVapidKey, privateVapidKey);
} else {
  console.warn('WARNING: VAPID keys not set. Push notifications will not work.');
}

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
    CREATE TABLE IF NOT EXISTS push_subscriptions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      userId INTEGER NOT NULL,
      endpoint TEXT NOT NULL,
      p256dh TEXT NOT NULL,
      auth TEXT NOT NULL,
      UNIQUE(userId, endpoint)
    );
    CREATE TABLE IF NOT EXISTS groups (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      avatar TEXT,
      creatorId INTEGER NOT NULL,
      createdAt DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS group_members (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      groupId INTEGER NOT NULL,
      userId INTEGER NOT NULL,
      role TEXT DEFAULT 'member',
      joinedAt DATETIME DEFAULT CURRENT_TIMESTAMP,
      UNIQUE(groupId, userId)
    );
    CREATE TABLE IF NOT EXISTS group_messages (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      groupId INTEGER NOT NULL,
      senderId INTEGER NOT NULL,
      senderName TEXT,
      text TEXT,
      fileUrl TEXT,
      fileType TEXT,
      fileName TEXT,
      fileSize INTEGER,
      timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    );
  `);
  
  try {
    await db.execute('ALTER TABLE users ADD COLUMN passwordHash TEXT');
  } catch (e) {}
  try {
    await db.execute('ALTER TABLE users ADD COLUMN encryptedPrivKey TEXT');
  } catch (e) {}
  try {
    await db.execute('ALTER TABLE users ADD COLUMN lastSeen INTEGER');
  } catch (e) {}
  try {
    await db.execute('ALTER TABLE users ADD COLUMN hideOnlineStatus INTEGER DEFAULT 0');
  } catch (e) {}
  try {
    await db.execute('ALTER TABLE messages ADD COLUMN isRead INTEGER DEFAULT 0');
  } catch (e) {}
  console.log('DB ready');

  // Clean up direct messages older than 24 hours periodically (every 10 minutes)
  setInterval(async () => {
    try {
      await db.execute("DELETE FROM messages WHERE timestamp < DATETIME('now', '-24 hours')");
      await db.execute("DELETE FROM group_messages WHERE timestamp < DATETIME('now', '-7 days')");
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

app.get('/api/vapidPublicKey', (req, res) => {
  res.json({ publicKey: publicVapidKey });
});

app.post('/api/subscribe', async (req, res) => {
  const { userId, subscription } = req.body;
  if (!userId || !subscription) return res.status(400).json({ error: 'Bad Request' });

  try {
    await dbRun(
      'INSERT OR IGNORE INTO push_subscriptions (userId, endpoint, p256dh, auth) VALUES (?, ?, ?, ?)',
      [userId, subscription.endpoint, subscription.keys.p256dh, subscription.keys.auth]
    );
    res.status(201).json({ ok: true });
  } catch (e) {
    console.error('Subscribe err:', e);
    res.status(500).json({ error: e.message });
  }
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
      
      // Update last seen
      await dbRun('UPDATE users SET lastSeen = ? WHERE id = ?', [Date.now(), existing.id]);
      
      // Return existing user info so client can decrypt their private key
      return res.json({ 
        id: existing.id, 
        username: existing.username, 
        publicKey: existing.publicKey,
        encryptedPrivKey: existing.encryptedPrivKey,
        hideOnlineStatus: existing.hideOnlineStatus || 0
      });
    }

    if (!publicKey || !encryptedPrivKey) {
      return res.status(400).json({ error: 'Для регистрации нужны ключи шифрования' });
    }

    const now = Date.now();
    const result = await dbRun('INSERT INTO users (username, publicKey, passwordHash, encryptedPrivKey, lastSeen, hideOnlineStatus) VALUES (?, ?, ?, ?, ?, 0)', [cleanUser, publicKey, hash, encryptedPrivKey, now]);
    res.json({ id: result.lastID, username: cleanUser, publicKey, encryptedPrivKey, hideOnlineStatus: 0 });
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
      await dbRun('DELETE FROM push_subscriptions WHERE userId = ?', [user.id]);
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

app.get('/api/users/statuses', async (req, res) => {
  try {
    const users = await dbAll('SELECT id, lastSeen, hideOnlineStatus FROM users');
    const statuses = {};
    for (const u of users) {
      const isConnected = userSockets.has(String(u.id));
      const isHidden = u.hideOnlineStatus === 1;
      statuses[u.id] = {
        isOnline: isConnected && !isHidden,
        lastSeen: isHidden ? null : u.lastSeen,
        hidden: isHidden
      };
    }
    res.json(statuses);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/user/privacy', async (req, res) => {
  const { userId, hideOnlineStatus } = req.body;
  if (!userId) return res.status(400).json({ error: 'Missing userId' });
  try {
    const val = hideOnlineStatus ? 1 : 0;
    await dbRun('UPDATE users SET hideOnlineStatus = ? WHERE id = ?', [val, userId]);
    
    // Broadcast status change to all clients
    const isConnected = userSockets.has(String(userId));
    io.emit('user_status_change', {
      userId: Number(userId),
      isOnline: val === 1 ? false : isConnected,
      lastSeen: val === 1 ? null : Date.now(),
      hidden: val === 1
    });
    
    res.json({ success: true, hideOnlineStatus: val });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/users/:id', async (req, res) => {
  const user = await dbGet('SELECT id, username, publicKey, lastSeen, hideOnlineStatus FROM users WHERE id = ?', [req.params.id]);
  if (user) res.json(user); else res.status(404).json({ error: 'Not found' });
});

app.get('/api/messages/:userId/:friendId', async (req, res) => {
  const { userId, friendId } = req.params;
  const messages = await dbAll(`
    SELECT id, senderId, receiverId,
      CASE WHEN senderId = ? THEN senderCopy ELSE encryptedContent END as encryptedContent,
      timestamp,
      isRead
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

// ─── Group Chats API ─────────────────────────────────────────────────────────

app.post('/api/groups/create', async (req, res) => {
  const { name, avatar, creatorId, memberIds } = req.body;
  if (!name || !creatorId) return res.status(400).json({ error: 'Missing name or creatorId' });
  try {
    const creator = await dbGet('SELECT username FROM users WHERE id = ?', [creatorId]);
    const groupName = name.trim();
    const g = await dbRun('INSERT INTO groups (name, avatar, creatorId) VALUES (?, ?, ?)', [
      groupName,
      avatar || '👥',
      creatorId
    ]);
    const groupId = g.lastID;
    
    // Creator is admin
    await dbRun('INSERT OR IGNORE INTO group_members (groupId, userId, role) VALUES (?, ?, ?)', [groupId, creatorId, 'admin']);
    
    const members = Array.isArray(memberIds) ? memberIds : [];
    for (const mId of members) {
      if (Number(mId) !== Number(creatorId)) {
        await dbRun('INSERT OR IGNORE INTO group_members (groupId, userId, role) VALUES (?, ?, ?)', [groupId, Number(mId), 'member']);
      }
    }

    // System welcome message
    await dbRun(`
      INSERT INTO group_messages (groupId, senderId, senderName, text)
      VALUES (?, ?, ?, ?)
    `, [groupId, 0, 'Система', `Группа «${groupName}» создана пользователем ${creator ? creator.username : ''}`]);

    const groupData = {
      id: groupId,
      name: groupName,
      avatar: avatar || '👥',
      creatorId,
      memberCount: members.length + 1,
      lastMessage: `Группа «${groupName}» создана`,
      lastSenderName: 'Система',
      lastMessageTime: new Date().toISOString()
    };

    // Join online members to group socket room and notify them
    for (const mId of [creatorId, ...members]) {
      const sids = userSockets.get(String(mId));
      if (sids) {
        for (const sid of sids) {
          const s = io.sockets.sockets.get(sid);
          if (s) s.join('group_' + groupId);
          io.to(sid).emit('group_created', groupData);
        }
      }
    }

    res.json({ success: true, group: groupData });
  } catch(e) {
    console.error('Group create err:', e);
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/groups/my/:userId', async (req, res) => {
  const { userId } = req.params;
  try {
    const groups = await dbAll(`
      SELECT g.id, g.name, g.avatar, g.creatorId, g.createdAt,
             (SELECT COUNT(*) FROM group_members gm2 WHERE gm2.groupId = g.id) as memberCount,
             (SELECT text FROM group_messages gm3 WHERE gm3.groupId = g.id ORDER BY timestamp DESC LIMIT 1) as lastMessage,
             (SELECT senderName FROM group_messages gm3 WHERE gm3.groupId = g.id ORDER BY timestamp DESC LIMIT 1) as lastSenderName,
             (SELECT timestamp FROM group_messages gm3 WHERE gm3.groupId = g.id ORDER BY timestamp DESC LIMIT 1) as lastMessageTime
      FROM groups g
      JOIN group_members gm ON g.id = gm.groupId
      WHERE gm.userId = ?
      GROUP BY g.id
      ORDER BY COALESCE(lastMessageTime, g.createdAt) DESC
    `, [userId]);
    res.json(groups || []);
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/groups/:groupId/messages', async (req, res) => {
  const { groupId } = req.params;
  try {
    const messages = await dbAll(`
      SELECT gm.id, gm.groupId, gm.senderId, gm.senderName, gm.text, gm.fileUrl, gm.fileType, gm.fileName, gm.fileSize, gm.timestamp,
             u.username
      FROM group_messages gm
      LEFT JOIN users u ON u.id = gm.senderId
      WHERE gm.groupId = ?
      ORDER BY gm.timestamp ASC
    `, [groupId]);
    res.json(messages || []);
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/groups/:groupId/members', async (req, res) => {
  const { groupId } = req.params;
  try {
    const members = await dbAll(`
      SELECT u.id, u.username, u.lastSeen, u.hideOnlineStatus, gm.role
      FROM group_members gm
      JOIN users u ON u.id = gm.userId
      WHERE gm.groupId = ?
      ORDER BY gm.role DESC, u.username ASC
    `, [groupId]);
    res.json(members || []);
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/groups/:groupId/add-members', async (req, res) => {
  const { groupId } = req.params;
  const { memberIds } = req.body;
  if (!Array.isArray(memberIds)) return res.status(400).json({ error: 'Missing memberIds array' });
  try {
    for (const mId of memberIds) {
      await dbRun('INSERT OR IGNORE INTO group_members (groupId, userId, role) VALUES (?, ?, ?)', [groupId, Number(mId), 'member']);
      const sids = userSockets.get(String(mId));
      if (sids) {
        for (const sid of sids) {
          const s = io.sockets.sockets.get(sid);
          if (s) s.join('group_' + groupId);
          io.to(sid).emit('group_added', { groupId: Number(groupId) });
        }
      }
    }
    res.json({ success: true });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/groups/:groupId/leave', async (req, res) => {
  const { groupId } = req.params;
  const { userId } = req.body;
  if (!userId) return res.status(400).json({ error: 'Missing userId' });
  try {
    await dbRun('DELETE FROM group_members WHERE groupId = ? AND userId = ?', [groupId, userId]);
    const sids = userSockets.get(String(userId));
    if (sids) {
      for (const sid of sids) {
        const s = io.sockets.sockets.get(sid);
        if (s) s.leave('group_' + groupId);
      }
    }
    res.json({ success: true });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

// ─── Socket.IO ────────────────────────────────────────────────────────────────

io.on('connection', (socket) => {
  console.log('Connected:', socket.id);

  socket.on('register', async (userId) => {
    const uid = String(userId);
    if (!userSockets.has(uid)) userSockets.set(uid, new Set());
    userSockets.get(uid).add(socket.id);
    socket.data.userId = uid;
    
    // Auto-join all group rooms this user belongs to
    try {
      const myGroups = await dbAll('SELECT groupId FROM group_members WHERE userId = ?', [uid]);
      for (const g of myGroups) {
        socket.join('group_' + g.groupId);
      }
    } catch(e){}

    const now = Date.now();
    await dbRun('UPDATE users SET lastSeen = ? WHERE id = ?', [now, uid]);

    try {
      const u = await dbGet('SELECT hideOnlineStatus FROM users WHERE id = ?', [uid]);
      const isHidden = u && u.hideOnlineStatus === 1;
      
      io.emit('user_status_change', {
        userId: Number(uid),
        isOnline: !isHidden,
        lastSeen: isHidden ? null : now,
        hidden: isHidden
      });
    } catch(e){}

    console.log(`User ${uid} registered (socket ${socket.id}). Online: ${[...userSockets.keys()]}`);
  });

  socket.on('get_all_statuses', async () => {
    try {
      const users = await dbAll('SELECT id, lastSeen, hideOnlineStatus FROM users');
      const statuses = {};
      for (const u of users) {
        const isConnected = userSockets.has(String(u.id));
        const isHidden = u.hideOnlineStatus === 1;
        statuses[u.id] = {
          isOnline: isConnected && !isHidden,
          lastSeen: isHidden ? null : u.lastSeen,
          hidden: isHidden
        };
      }
      socket.emit('all_statuses', statuses);
    } catch(e){}
  });

  socket.on('private_message', async (data) => {
    const { senderId, receiverId, encryptedContent, senderCopy } = data;
    console.log(`MSG from ${senderId} to ${receiverId}`);

    // Save to DB
    try {
      const result = await dbRun(
        'INSERT INTO messages (senderId, receiverId, encryptedContent, senderCopy, isRead) VALUES (?, ?, ?, ?, 0)',
        [senderId, receiverId, encryptedContent, senderCopy || null]
      );

      const message = {
        id: result.lastID,
        senderId,
        receiverId,
        encryptedContent,
        timestamp: new Date().toISOString(),
        isRead: 0
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
      
      // Push notification
      try {
        if (publicVapidKey && privateVapidKey) {
          const senderUser = await dbGet('SELECT username FROM users WHERE id = ?', [senderId]);
          const subs = await dbAll('SELECT * FROM push_subscriptions WHERE userId = ?', [receiverId]);
          const payload = JSON.stringify({
            title: 'Новое сообщение',
            body: `Вам написал ${senderUser ? senderUser.username : 'кто-то'}`,
            icon: '/icon.png'
          });
          
          for (const sub of subs) {
            const pushConfig = {
              endpoint: sub.endpoint,
              keys: { p256dh: sub.p256dh, auth: sub.auth }
            };
            webpush.sendNotification(pushConfig, payload).catch(async (err) => {
              if (err.statusCode === 410 || err.statusCode === 404) {
                await dbRun('DELETE FROM push_subscriptions WHERE id = ?', [sub.id]);
              }
            });
          }
        }
      } catch (pushErr) {
        console.error('Push error:', pushErr);
      }

      // Confirm to sender
      socket.emit('message_sent', { ...message, encryptedContent: senderCopy || encryptedContent });
    } catch (e) {
      console.error('Error saving message:', e);
      socket.emit('error', { message: 'Failed to send' });
    }
  });

  socket.on('mark_read', async (data) => {
    const { senderId, receiverId } = data;
    if (!senderId || !receiverId) return;
    try {
      await dbRun('UPDATE messages SET isRead = 1 WHERE senderId = ? AND receiverId = ? AND isRead = 0', [senderId, receiverId]);
      
      const sSockets = userSockets.get(String(senderId));
      if (sSockets) {
        for (const sid of sSockets) {
          io.to(sid).emit('messages_read', { readerId: receiverId, senderId });
        }
      }
    } catch (e) {
      console.error('mark_read error:', e);
    }
  });

  // --- WebRTC Signaling ---
  socket.on('webrtc_offer', (data) => {
    // data: { toId, fromId, offer, isVideo }
    const rSockets = userSockets.get(String(data.toId));
    if (rSockets) {
      for (const sid of rSockets) io.to(sid).emit('webrtc_offer', data);
    }
  });

  socket.on('webrtc_answer', (data) => {
    // data: { toId, fromId, answer }
    const rSockets = userSockets.get(String(data.toId));
    if (rSockets) {
      for (const sid of rSockets) io.to(sid).emit('webrtc_answer', data);
    }
  });

  socket.on('webrtc_ice', (data) => {
    // data: { toId, fromId, candidate }
    const rSockets = userSockets.get(String(data.toId));
    if (rSockets) {
      for (const sid of rSockets) io.to(sid).emit('webrtc_ice', data);
    }
  });

  socket.on('webrtc_reject', (data) => {
    // data: { toId, fromId }
    const rSockets = userSockets.get(String(data.toId));
    if (rSockets) {
      for (const sid of rSockets) io.to(sid).emit('webrtc_reject', data);
    }
  });

  socket.on('webrtc_hangup', (data) => {
    // data: { toId, fromId }
    const rSockets = userSockets.get(String(data.toId));
    if (rSockets) {
      for (const sid of rSockets) io.to(sid).emit('webrtc_hangup', data);
    }
  });

  // --- Real-time Guaranteed Audio/Video Relay (Zero-NAT Fallback) ---
  socket.on('call_audio', (data) => {
    const rSockets = userSockets.get(String(data.toId));
    if (rSockets) {
      for (const sid of rSockets) io.to(sid).emit('call_audio', data);
    }
  });

  // Native Opus compressed stream (WebCodecs)
  socket.on('call_audio_opus', (data) => {
    const rSockets = userSockets.get(String(data.toId));
    if (rSockets) {
      for (const sid of rSockets) io.to(sid).emit('call_audio_opus', data);
    }
  });

  // IMA ADPCM compressed stream (Universal fallback)
  socket.on('call_audio_adpcm', (data) => {
    const rSockets = userSockets.get(String(data.toId));
    if (rSockets) {
      for (const sid of rSockets) io.to(sid).emit('call_audio_adpcm', data);
    }
  });

  // MediaRecorder blob relay (for iOS Safari)
  socket.on('call_audio_blob', (data) => {
    const rSockets = userSockets.get(String(data.toId));
    if (rSockets) {
      for (const sid of rSockets) io.to(sid).emit('call_audio_blob', data);
    }
  });

  socket.on('call_video_frame', (data) => {
    const rSockets = userSockets.get(String(data.toId));
    if (rSockets) {
      for (const sid of rSockets) io.to(sid).emit('call_video_frame', data);
    }
  });

  socket.on('webrtc_hangup', (data) => {
    // data: { toId, fromId }
    const rSockets = userSockets.get(String(data.toId));
    if (rSockets) {
      for (const sid of rSockets) io.to(sid).emit('webrtc_hangup', data);
    }
  });

  // Group Messaging
  socket.on('send_group_message', async (data) => {
    const { groupId, senderId, senderName, text, fileUrl, fileType, fileName, fileSize } = data;
    if (!groupId || !senderId) return;
    try {
      const res = await dbRun(`
        INSERT INTO group_messages (groupId, senderId, senderName, text, fileUrl, fileType, fileName, fileSize)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      `, [groupId, senderId, senderName, text || null, fileUrl || null, fileType || null, fileName || null, fileSize || null]);

      const msgObj = {
        id: res.lastID,
        groupId: Number(groupId),
        senderId: Number(senderId),
        senderName,
        text,
        fileUrl,
        fileType,
        fileName,
        fileSize,
        timestamp: new Date().toISOString()
      };

      io.to('group_' + groupId).emit('new_group_message', msgObj);
    } catch(e) {
      console.error('send_group_message err:', e);
    }
  });

  socket.on('group_typing', (data) => {
    if (data && data.groupId) {
      socket.to('group_' + data.groupId).emit('group_user_typing', data);
    }
  });

  socket.on('disconnect', async () => {
    const uid = socket.data.userId;
    if (uid && userSockets.has(uid)) {
      userSockets.get(uid).delete(socket.id);
      if (userSockets.get(uid).size === 0) {
        userSockets.delete(uid);
        
        const now = Date.now();
        await dbRun('UPDATE users SET lastSeen = ? WHERE id = ?', [now, uid]);
        
        try {
          const u = await dbGet('SELECT hideOnlineStatus FROM users WHERE id = ?', [uid]);
          const isHidden = u && u.hideOnlineStatus === 1;
          
          io.emit('user_status_change', {
            userId: Number(uid),
            isOnline: false,
            lastSeen: isHidden ? null : now,
            hidden: isHidden
          });
        } catch(e){}
      }
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
