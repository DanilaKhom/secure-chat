const io = require('socket.io-client');
const crypto = require('crypto');

async function runTest() {
  // Wipe DB first
  await fetch('http://localhost:3000/api/wipe-db', { method: 'POST' });

  // Register User A
  let resA = await fetch('http://localhost:3000/api/register', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username: 'userA', password: '123', publicKey: 'pubA' })
  });
  let userA = await resA.json();

  // Register User B
  let resB = await fetch('http://localhost:3000/api/register', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username: 'userB', password: '123', publicKey: 'pubB' })
  });
  let userB = await resB.json();

  console.log('Registered:', userA.username, userB.username);

  // Connect sockets
  const socketA = io('http://localhost:3000', { transports: ['websocket'] });
  const socketB = io('http://localhost:3000', { transports: ['websocket'] });

  socketA.on('connect', () => socketA.emit('register', userA.id));
  socketB.on('connect', () => socketB.emit('register', userB.id));

  await new Promise(r => setTimeout(r, 500)); // wait for registration

  socketB.on('friend_request', (data) => {
    console.log('B received friend_request from:', data.senderName);
  });

  socketA.on('friend_accepted', (data) => {
    console.log('A received friend_accepted from:', data.accepterName);
  });

  // User A sends request to User B
  console.log('A sending request to B');
  await fetch('http://localhost:3000/api/friends/request', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ senderId: userA.id, receiverId: userB.id })
  });

  await new Promise(r => setTimeout(r, 500));

  // Check B's incoming requests
  let reqsB = await fetch(`http://localhost:3000/api/friends/requests/${userB.id}`).then(r => r.json());
  console.log('B incoming requests:', reqsB.map(r => r.username));

  // User B accepts
  console.log('B accepting request');
  await fetch('http://localhost:3000/api/friends/accept', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ senderId: userA.id, receiverId: userB.id })
  });

  await new Promise(r => setTimeout(r, 500));

  // Check B's friends
  let friendsB = await fetch(`http://localhost:3000/api/friends/${userB.id}`).then(r => r.json());
  console.log('B friends:', friendsB.map(f => f.username));

  // Check A's friends
  let friendsA = await fetch(`http://localhost:3000/api/friends/${userA.id}`).then(r => r.json());
  console.log('A friends:', friendsA.map(f => f.username));

  socketA.disconnect();
  socketB.disconnect();
  process.exit(0);
}
runTest().catch(console.error);
