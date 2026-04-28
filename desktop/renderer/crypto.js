// BiCrypt Crypto — @noble (même logique que src/crypto/index.ts mobile)
import { ed25519, x25519 } from '../node_modules/@noble/curves/esm/ed25519.js';
import { xsalsa20poly1305 } from '../node_modules/@noble/ciphers/esm/salsa.js';
import { blake2b } from '../node_modules/@noble/hashes/esm/blake2.js';
import { randomBytes, bytesToHex, hexToBytes, utf8ToBytes } from '../node_modules/@noble/hashes/esm/utils.js';

const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

export function toBase64(bytes) {
  let r = '', i = 0;
  while (i < bytes.length) {
    const b0 = bytes[i++];
    const b1 = i < bytes.length ? bytes[i++] : undefined;
    const b2 = i < bytes.length ? bytes[i++] : undefined;
    r += B64[b0 >> 2];
    r += B64[((b0 & 3) << 4) | (b1 !== undefined ? b1 >> 4 : 0)];
    r += b1 !== undefined ? B64[((b1 & 15) << 2) | (b2 !== undefined ? b2 >> 6 : 0)] : '=';
    r += b2 !== undefined ? B64[b2 & 63] : '=';
  }
  return r;
}

export function fromBase64(b64) {
  const clean = b64.replace(/=/g, '');
  const out = new Uint8Array(Math.floor(clean.length * 3 / 4));
  let j = 0;
  for (let i = 0; i < clean.length; i += 4) {
    const e0 = B64.indexOf(clean[i] ?? '');
    const e1 = B64.indexOf(clean[i+1] ?? '');
    const e2 = B64.indexOf(clean[i+2] ?? 'A');
    const e3 = B64.indexOf(clean[i+3] ?? 'A');
    if (e1 >= 0) { out[j++] = (e0 << 2) | (e1 >> 4); }
    if (e2 >= 0 && clean[i+2]) { out[j++] = ((e1 & 15) << 4) | (e2 >> 2); }
    if (e3 >= 0 && clean[i+3]) { out[j++] = ((e2 & 3) << 6) | e3; }
  }
  return out.slice(0, j);
}

function edPubToX25519(hex)  { return ed25519.utils.toMontgomery(hexToBytes(hex)); }
function edPrivToX25519(hex) { return ed25519.utils.toMontgomerySecret(hexToBytes(hex)); }
const dec = new TextDecoder();

export function generateIdentity(displayName) {
  const priv = ed25519.utils.randomSecretKey();
  const pub  = ed25519.getPublicKey(priv);
  return {
    id: bytesToHex(randomBytes(16)),
    pubkey: bytesToHex(pub),
    privkey: bytesToHex(priv),
    displayName,
    createdAt: Date.now(),
  };
}

// v2.6 : signe le timestamp aussi → un MITM ne peut plus rejouer en falsifiant ts.
// Compat : decrypt accepte v2 (sans ts) ou v3 (avec ts).
export function encryptMessage(plaintext, recipientPubHex, senderPrivHex, timestamp) {
  const ts = timestamp ?? Date.now();
  const recipX = edPubToX25519(recipientPubHex);
  const ephPriv = randomBytes(32);
  const ephPub  = x25519.getPublicKey(ephPriv);
  const nonce   = randomBytes(24);
  const shared  = x25519.getSharedSecret(ephPriv, recipX);
  const cipher  = xsalsa20poly1305(shared, nonce).encrypt(utf8ToBytes(plaintext));
  const ephHex  = bytesToHex(ephPub);
  const ctB64   = toBase64(cipher);
  const nB64    = toBase64(nonce);
  const sig     = signMessage(`${ephHex}|${ctB64}|${nB64}|${ts}`, senderPrivHex);
  return { ciphertext: ctB64, nonce: nB64, ephPub: ephHex, sig, timestamp: ts };
}

export function decryptMessage(ctB64, nB64, senderPubHex, recipPrivHex, ephHex, sig, timestamp) {
  try {
    if (!ephHex || !sig) return null;
    let ok = false;
    if (timestamp !== undefined) {
      ok = verifySignature(`${ephHex}|${ctB64}|${nB64}|${timestamp}`, sig, senderPubHex);
    }
    if (!ok) ok = verifySignature(`${ephHex}|${ctB64}|${nB64}`, sig, senderPubHex);
    if (!ok) return null;
    const shared = x25519.getSharedSecret(edPrivToX25519(recipPrivHex), hexToBytes(ephHex));
    const plain  = xsalsa20poly1305(shared, fromBase64(nB64)).decrypt(fromBase64(ctB64));
    return dec.decode(plain);
  } catch { return null; }
}

export function encryptChannelMessage(plaintext, keyB64) {
  const key   = fromBase64(keyB64);
  const nonce = randomBytes(24);
  const ct    = xsalsa20poly1305(key, nonce).encrypt(utf8ToBytes(plaintext));
  return { ciphertext: toBase64(ct), nonce: toBase64(nonce) };
}

export function decryptChannelMessage(ctB64, nB64, keyB64) {
  try {
    const plain = xsalsa20poly1305(fromBase64(keyB64), fromBase64(nB64)).decrypt(fromBase64(ctB64));
    return dec.decode(plain);
  } catch { return null; }
}

export function generateChannelKey() { return toBase64(randomBytes(32)); }

export function signMessage(msg, privHex) {
  return toBase64(ed25519.sign(utf8ToBytes(msg), hexToBytes(privHex)));
}

export function verifySignature(msg, sigB64, pubHex) {
  try { return ed25519.verify(fromBase64(sigB64), utf8ToBytes(msg), hexToBytes(pubHex)); }
  catch { return false; }
}

export function hashPin(pin) {
  return bytesToHex(blake2b(utf8ToBytes(pin), { dkLen: 32 }));
}

export function derivePublicChannelKey(channelId) {
  return toBase64(blake2b(utf8ToBytes('bicrypt:channel:' + channelId), { dkLen: 32 }));
}

export function encodeIdentityQR(identity) {
  return JSON.stringify({ v: 1, id: identity.id, pk: identity.pubkey, n: identity.displayName });
}

export function decodeIdentityQR(raw) {
  try {
    const s = raw.trim();
    // Extrait le JSON même si du texte l'entoure
    const match = s.match(/\{[\s\S]*\}/);
    const p = JSON.parse(match ? match[0] : s);
    if (p.v !== 1 || typeof p.pk !== 'string' || p.pk.length !== 64) return null;
    if (typeof p.id !== 'string' || p.id.length < 8) return null;
    return { id: p.id, pubkey: p.pk, displayName: p.n || 'Inconnu', addedAt: Date.now() };
  } catch { return null; }
}

// Chiffrement local — clé aléatoire 32 bytes stockée dans le keychain OS.
// Legacy v1.9 : clé dérivée d'une string fixe (identique pour tous → peu sûre).
// v2.0+ : clé random par install, lecture du disque seule ne suffit plus.
const LEGACY_LOCAL_KEY = derivePublicChannelKey('bicrypt:local-storage-v1');
let _localKey = null;

export function setLocalKey(keyB64) { _localKey = keyB64; }
export function hasLocalKey()       { return _localKey !== null; }
export function newLocalKey()       { return generateChannelKey(); }

export function encryptLocal(plaintext) {
  if (!_localKey) { throw new Error('localkey not initialised'); }
  const { ciphertext, nonce } = encryptChannelMessage(plaintext, _localKey);
  return `enc1:${nonce}:${ciphertext}`;
}

export function decryptLocal(raw) {
  if (!raw.startsWith('enc1:')) return raw;
  const parts = raw.split(':');
  if (parts.length < 3) return null;
  const nonce = parts[1];
  const ct = parts.slice(2).join(':');
  if (_localKey) {
    const plain = decryptChannelMessage(ct, nonce, _localKey);
    if (plain !== null) return plain;
  }
  // Fallback legacy v1.9 : permet de migrer les données existantes.
  return decryptChannelMessage(ct, nonce, LEGACY_LOCAL_KEY);
}
