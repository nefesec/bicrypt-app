// Storage local — localStorage chiffré + keychain système pour la privkey
import { encryptLocal, decryptLocal, hashPin, setLocalKey, newLocalKey } from './crypto.js';

// Initialise la clé locale : récupère du keychain ou en crée une nouvelle.
// Doit être appelé au tout début du bootstrap, avant toute lecture/écriture chiffrée.
export async function initLocalStorage() {
  let key = await window.bicrypt.keychainGet('local-storage-key');
  if (!key) {
    key = newLocalKey();
    await window.bicrypt.keychainSet('local-storage-key', key);
  }
  setLocalKey(key);
}

const KEYS = {
  IDENTITY:    'bicrypt:identity',
  CONTACTS:    'bicrypt:contacts',
  CHANNELS:    'bicrypt:channels',
  MESSAGES:    id => `bicrypt:messages:${id}`,
  PIN_HASH:    'bicrypt:pin_hash',
  PIN_ATTEMPTS:'bicrypt:pin_attempts',
  PIN_LOCKED:  'bicrypt:pin_locked_until',
};

function get(key) { return localStorage.getItem(key); }
function set(key, val) {
  try { localStorage.setItem(key, val); }
  catch (e) {
    if (e.name === 'QuotaExceededError' || e.code === 22) {
      // Purge les anciens messages pour libérer de la place
      for (const k of Object.keys(localStorage)) {
        if (k.startsWith('bicrypt:messages:')) { localStorage.removeItem(k); }
      }
      try { localStorage.setItem(key, val); } catch (_) {}
    }
  }
}
function del(key) { localStorage.removeItem(key); }

function safeParse(raw, fallback) {
  if (!raw) return fallback;
  try { return JSON.parse(raw); } catch { return fallback; }
}

// ── Identity ──────────────────────────────────────────────────────────────────

export async function saveIdentity(identity) {
  const pub = { id: identity.id, pubkey: identity.pubkey, displayName: identity.displayName, createdAt: identity.createdAt };
  set(KEYS.IDENTITY, JSON.stringify(pub));
  // Privkey dans le keychain système (chiffré par l'OS)
  await window.bicrypt.keychainSet('privkey:' + identity.id, identity.privkey);
}

export async function loadIdentity() {
  const raw = get(KEYS.IDENTITY);
  const pub = safeParse(raw, {});
  if (!pub.id || !pub.pubkey) return null;
  const privkey = await window.bicrypt.keychainGet('privkey:' + pub.id);
  if (!privkey) return null;
  return { ...pub, privkey };
}

export async function clearAllData() {
  const raw = get(KEYS.IDENTITY);
  const pub = safeParse(raw, {});
  if (pub.id) {
    await window.bicrypt.keychainDelete('privkey:' + pub.id);
    await window.bicrypt.keychainDelete('biometric_gate');
  }
  await window.bicrypt.keychainDelete('local-storage-key');
  localStorage.clear();
}

// ── Contacts ──────────────────────────────────────────────────────────────────

export function loadContacts() { return safeParse(get(KEYS.CONTACTS), []); }
export function saveContacts(c) { set(KEYS.CONTACTS, JSON.stringify(c)); }
export function addContact(c) {
  const list = loadContacts();
  if (!list.find(x => x.id === c.id)) { list.push(c); saveContacts(list); }
}
export function removeContact(id) { saveContacts(loadContacts().filter(c => c.id !== id)); }

// ── Channels ──────────────────────────────────────────────────────────────────

export function loadChannels() { return safeParse(get(KEYS.CHANNELS), []); }
export function saveChannels(ch) { set(KEYS.CHANNELS, JSON.stringify(ch)); }
export function addChannel(ch) {
  const list = loadChannels();
  if (!list.find(x => x.id === ch.id)) { list.push(ch); saveChannels(list); }
}
export function leaveChannel(id) {
  saveChannels(loadChannels().filter(c => c.id !== id));
  del(KEYS.MESSAGES(id));
}

// ── Messages ──────────────────────────────────────────────────────────────────

export function loadMessages(chatId) {
  const raw = get(KEYS.MESSAGES(chatId));
  if (!raw) return [];
  const dec = decryptLocal(raw);
  return safeParse(dec, []);
}

export function saveMessages(chatId, msgs) {
  const trimmed = msgs.slice(-500);
  set(KEYS.MESSAGES(chatId), encryptLocal(JSON.stringify(trimmed)));
}

export function appendMessage(chatId, msg) {
  const msgs = loadMessages(chatId);
  if (msgs.some(m => m.id === msg.id)) return; // dédup
  msgs.push(msg);
  saveMessages(chatId, msgs);
}

export function nukeHistory() {
  for (const key of Object.keys(localStorage)) {
    if (key.startsWith('bicrypt:messages:')) del(key);
  }
  del(KEYS.CHANNELS);
}

// ── PIN (chiffré) ─────────────────────────────────────────────────────────────

export function savePinHash(hash) { set(KEYS.PIN_HASH, encryptLocal(hash)); }
export function loadPinHash() {
  const raw = get(KEYS.PIN_HASH);
  return raw ? decryptLocal(raw) : null;
}
export function hasPinSet() { return get(KEYS.PIN_HASH) !== null; }

export function savePinLockout(attempts, lockedUntil) {
  set(KEYS.PIN_ATTEMPTS, encryptLocal(String(attempts)));
  if (lockedUntil !== null) set(KEYS.PIN_LOCKED, encryptLocal(String(lockedUntil)));
  else del(KEYS.PIN_LOCKED);
}
export function loadPinLockout() {
  const ra = get(KEYS.PIN_ATTEMPTS);
  const rl = get(KEYS.PIN_LOCKED);
  return {
    attempts:    ra ? parseInt(decryptLocal(ra) ?? '0', 10) : 0,
    lockedUntil: rl ? parseInt(decryptLocal(rl) ?? '0', 10) : null,
  };
}
export function resetPinLockout() { del(KEYS.PIN_ATTEMPTS); del(KEYS.PIN_LOCKED); }
