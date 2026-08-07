import crypto from 'crypto';

const { subtle } = crypto.webcrypto;

function buf2b64(b){
  const bytes=new Uint8Array(b);
  let binary='';
  for(let i=0;i<bytes.length;i++){
    binary+=String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

function b642buf(s){
  const b=atob(s),a=new Uint8Array(b.length);
  for(let i=0;i<b.length;i++)a[i]=b.charCodeAt(i);
  return a.buffer;
}

async function getKek(password){
  const enc = new TextEncoder();
  const keyMaterial = await subtle.importKey('raw', enc.encode(password), {name: 'PBKDF2'}, false, ['deriveKey']);
  return subtle.deriveKey(
    {name: 'PBKDF2', salt: enc.encode('friendlychat_salt'), iterations: 100000, hash: 'SHA-256'},
    keyMaterial, {name: 'AES-GCM', length: 256}, false, ['encrypt', 'decrypt']
  );
}

async function wrapPrivKey(privJwk, password){
  const kek = await getKek(password);
  const iv = crypto.webcrypto.getRandomValues(new Uint8Array(12));
  const enc = await subtle.encrypt(
    {name: 'AES-GCM', iv}, kek, new TextEncoder().encode(JSON.stringify(privJwk))
  );
  return { c: buf2b64(enc), v: buf2b64(iv.buffer) };
}

async function unwrapPrivKey(wrappedObj, password){
  const kek = await getKek(password);
  const dec = await subtle.decrypt(
    {name: 'AES-GCM', iv: new Uint8Array(b642buf(wrappedObj.v))}, kek, b642buf(wrappedObj.c)
  );
  return JSON.parse(new TextDecoder().decode(dec));
}

async function run() {
  const username = "testuser_api_" + Date.now();
  const password = "mysecretpassword123";
  const dummyPriv = { kty: "RSA", n: "dummy" };
  const wrapped = await wrapPrivKey(dummyPriv, password);
  
  console.log("Registering...");
  let res = await fetch('http://localhost:3000/api/register', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      username: username,
      password: password,
      publicKey: JSON.stringify({ kty: "RSA", e: "AQAB" }),
      encryptedPrivKey: JSON.stringify(wrapped)
    })
  });
  let data = await res.json();
  console.log("Registered:", data);
  
  console.log("Logging in...");
  res = await fetch('http://localhost:3000/api/register', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      username: username,
      password: password,
      publicKey: "dummy",
      encryptedPrivKey: "dummy"
    })
  });
  data = await res.json();
  console.log("Login response:", data);
  
  console.log("Unwrapping...");
  const unwrapped = await unwrapPrivKey(JSON.parse(data.encryptedPrivKey), password);
  console.log("Unwrapped success:", unwrapped);
}

run().catch(console.error);
