import QRCode from 'qrcode';
import {
  generateIdentity, encryptMessage, decryptMessage,
  encryptChannelMessage, decryptChannelMessage,
  hashPin, derivePublicChannelKey,
  encodeIdentityQR, decodeIdentityQR,
  signMessage, verifySignature,
  generateChannelKey,
} from './crypto.js';
import {
  saveIdentity, loadIdentity, clearAllData,
  loadContacts, addContact, removeContact,
  loadChannels, addChannel, leaveChannel,
  loadMessages, appendMessage, nukeHistory,
  savePinHash, loadPinHash, hasPinSet,
  savePinLockout, loadPinLockout, resetPinLockout,
  initLocalStorage,
} from './storage.js';
const VERSION = '2.8.1';
const PIN_LENGTH = 6;
const MAX_ATTEMPTS = 5;
const LOCKOUT_MS = 15 * 60 * 1000;

// Canal général unique — toujours présent, auto-rejoint au démarrage
const GENERAL_CHANNEL = {
  id: 'public:general',
  name: 'Général',
  type: 'public',
  key: null, // initialisé après chargement crypto
  createdAt: 0,
  joinedAt: 0,
};

// ── Canaux publics disponibles ────────────────────────────────────────────────

const PUBLIC_GEO_CHANNELS = [
  { id: 'public:general', name: 'Général',  zone: 'Global'  },
  { id: 'public:fr',      name: 'France',   zone: 'Europe'  },
  { id: 'public:eu',      name: 'Europe',   zone: 'Europe'  },
  { id: 'public:us',      name: 'US',       zone: 'Amériques' },
  { id: 'public:latam',   name: 'LatAm',    zone: 'Amériques' },
  { id: 'public:asia',    name: 'Asie',     zone: 'Asie'    },
  { id: 'public:africa',  name: 'Afrique',  zone: 'Afrique' },
];

function randomChannelId() {
  const arr = new Uint8Array(12);
  crypto.getRandomValues(arr);
  return 'prv:' + Array.from(arr).map(b => b.toString(16).padStart(2, '0')).join('');
}

function buildPublicChannel(def) {
  return {
    id: def.id,
    name: def.name,
    type: 'public',
    key: derivePublicChannelKey(def.id),
    createdAt: 0,
    joinedAt: Date.now(),
  };
}

function generateChannelInvite(channel) {
  const payload = { v: 2, id: channel.id, name: channel.name, key: channel.key, issuer: identity?.pubkey || '' };
  const canonical = JSON.stringify(payload, Object.keys(payload).sort());
  const sig = signMessage(canonical, identity?.privkey || '');
  return JSON.stringify({ ...payload, sig });
}

function parseChannelInvite(raw) {
  const obj = JSON.parse(raw);
  if (obj.v !== 2) throw new Error('Format invalide');
  if (!obj.id || !obj.name || !obj.key) throw new Error('Champs manquants');
  if (!obj.id.startsWith('prv:')) throw new Error('Seules les invitations privées sont acceptées');
  if (obj.sig && obj.issuer) {
    const { sig, ...rest } = obj;
    const canonical = JSON.stringify(rest, Object.keys(rest).sort());
    if (!verifySignature(canonical, sig, obj.issuer)) throw new Error('Signature invalide');
  }
  return { id: obj.id, name: obj.name, type: 'private', key: obj.key, createdAt: Date.now(), joinedAt: Date.now() };
}

// ── État global ───────────────────────────────────────────────────────────────

let identity = null;
let currentScreen = 'loading';
let currentChat = null;   // { type: 'direct'|'channel', data: Contact|Channel }
let torStatus = 'offline';
let replayCache = new Set();

// Triple-tap nuke
let tapCount = 0;
let tapTimer = null;

// ── Routing ───────────────────────────────────────────────────────────────────

function show(screenId) {
  document.querySelectorAll('.screen').forEach(s => s.classList.remove('active'));
  const el = document.getElementById('screen-' + screenId);
  if (el) el.classList.add('active');
  currentScreen = screenId;
}

// ── Bootstrap ─────────────────────────────────────────────────────────────────

async function init() {
  render();
  show('loading');

  // Tor démarre automatiquement dans main.js — on attend le signal
  await waitForTor();

  // Clé locale (keychain) avant toute lecture chiffrée
  await initLocalStorage();

  // Identité
  identity = await loadIdentity();
  if (!identity) { show('onboarding'); return; }

  // PIN
  if (!hasPinSet()) {
    renderPin('create');
    show('pin');
  } else {
    renderPin('unlock');
    show('pin');
  }
}

function waitForTor() {
  return new Promise((resolve, reject) => {
    let done = false;

    function finish() {
      if (done) return;
      done = true;
      resolve();
    }

    // Polling toutes les 2s — fallback si l'événement est arrivé avant l'écoute
    const poll = setInterval(async () => {
      const { ready, progress } = await window.bicrypt.torStatus();
      updateLoadingProgress(progress);
      if (ready) { clearInterval(poll); finish(); }
    }, 2000);

    // Événements temps-réel
    window.bicrypt.onTorProgress(pct => {
      if (pct === -1) { clearInterval(poll); if (!done) { done = true; reject(new Error('Tor a planté')); } return; }
      updateLoadingProgress(pct);
      if (pct >= 100) { clearInterval(poll); finish(); }
    });

    window.bicrypt.onTorError(msg => {
      clearInterval(poll);
      document.getElementById('screen-loading').innerHTML = `
        <div style="color:var(--danger);font-size:13px;letter-spacing:2px;margin-bottom:16px">[ ERREUR TOR ]</div>
        <p style="color:var(--muted);font-size:12px;text-align:center;line-height:1.6;max-width:280px">${msg}</p>
        <p style="color:var(--muted);font-size:11px;text-align:center;margin-top:16px">
          Installe Tor : <span style="color:var(--accent)">sudo apt install tor</span>
        </p>
      `;
    });

    // Vérification immédiate (cas port déjà ouvert)
    window.bicrypt.torStatus().then(({ ready, progress }) => {
      updateLoadingProgress(progress);
      if (ready) { clearInterval(poll); finish(); }
    });
  });
}

function updateLoadingProgress(pct) {
  const el   = document.getElementById('loading-status');
  const fill = document.getElementById('tor-progress-fill');
  if (el)   { el.textContent = pct > 0 ? `Tor ${pct}%` : 'Démarrage Tor...'; }
  if (fill) { fill.style.width = pct + '%'; }
}

// ── Relay ─────────────────────────────────────────────────────────────────────

async function launchApp() {
  await window.bicrypt.relayConnect(identity.pubkey);

  // Canal général : initialise la clé et s'assure qu'il est en storage
  GENERAL_CHANNEL.key = derivePublicChannelKey(GENERAL_CHANNEL.id);
  const existing = loadChannels();
  const withoutOldGeo = existing.filter(c => !c.id.startsWith('geo:'));
  if (!withoutOldGeo.find(c => c.id === GENERAL_CHANNEL.id)) {
    withoutOldGeo.unshift({ ...GENERAL_CHANNEL, joinedAt: Date.now() });
  }
  if (withoutOldGeo.length !== existing.length) {
    localStorage.setItem('bicrypt:channels', JSON.stringify(withoutOldGeo));
  }

  // Rejoint le canal général côté relay
  window.bicrypt.relayJoin(GENERAL_CHANNEL.id);

  // Écoute des messages entrants
  window.bicrypt.onRelayMessage(onMessage);
  window.bicrypt.onRelayStatus(s => {
    torStatus = s;
    updateTorBadge();
  });

  // Statut initial
  const connected = await window.bicrypt.relayConnected();
  torStatus = connected ? 'connected' : 'connecting';

  renderHome();
  show('home');
}

// Anti-replay simple (ephPub ou nonce)
function isReplay(payload) {
  const age = Math.abs(Date.now() - (payload.timestamp || 0));
  if (age > 5 * 60 * 1000) return true;
  const key = payload.ephPub || payload.nonce;
  if (!key) return false;
  if (replayCache.has(key)) return true;
  if (replayCache.size > 2000) replayCache = new Set([...replayCache].slice(1000));
  replayCache.add(key);
  return false;
}

function onMessage(payload) {
  if (isReplay(payload)) return;

  if (payload.type === 'direct' && payload.ephPub && payload.sig) {
    const contact = loadContacts().find(c => c.pubkey === payload.from);
    if (!contact) return; // expéditeur inconnu — ignoré silencieusement
    const plain = decryptMessage(payload.ciphertext, payload.nonce, payload.from,
      identity.privkey, payload.ephPub, payload.sig, payload.timestamp);
    if (!plain) return;
    const chatId = [identity.id, contact.id].sort().join(':');
    appendMessage(chatId, {
      id: `${payload.from}:${payload.timestamp}:${payload.ephPub.slice(0, 8)}`,
      from: payload.from, to: identity.pubkey, content: plain,
      timestamp: payload.timestamp, type: 'direct', status: 'delivered', nonce: payload.nonce,
    });
    if (currentScreen === 'chat' && currentChat?.data?.pubkey === payload.from) {
      renderMessages();
    }
  } else if (payload.type === 'channel') {
    const channel = loadChannels().find(c => c.id === payload.to);
    if (!channel?.key) return;
    if (!payload.sig || !payload.from) return;
    // v3 : timestamp signé. v2 : sans (compat).
    const sdV3 = `${payload.to}|${payload.ciphertext}|${payload.nonce}|${payload.timestamp}`;
    const sdV2 = `${payload.to}|${payload.ciphertext}|${payload.nonce}`;
    if (!verifySignature(sdV3, payload.sig, payload.from)
        && !verifySignature(sdV2, payload.sig, payload.from)) return;
    const plain = decryptChannelMessage(payload.ciphertext, payload.nonce, channel.key);
    if (!plain) return;
    appendMessage(channel.id, {
      id: `${payload.from}:${payload.timestamp}:${payload.nonce.slice(0, 8)}`,
      from: payload.from, to: channel.id, content: plain,
      timestamp: payload.timestamp, type: 'channel', status: 'delivered', nonce: payload.nonce,
    });
    if (currentScreen === 'chat' && currentChat?.data?.id === channel.id) {
      renderMessages();
    }
  }
}

// ── Render ────────────────────────────────────────────────────────────────────

function render() {
  document.getElementById('app').innerHTML = `
    <!-- Loading -->
    <div id="screen-loading" class="screen">
      <div style="display:flex;align-items:baseline;gap:8px;margin-bottom:24px">
        <span class="logo" style="font-size:28px">BiCrypt</span>
        <span style="color:var(--muted);font-size:10px;letter-spacing:1px">v${VERSION}</span>
      </div>
      <div class="spinner"></div>
      <span id="loading-status" style="color:var(--muted);font-size:11px;letter-spacing:2px;margin-top:16px">Démarrage Tor...</span>
      <div id="tor-progress-bar" style="width:200px;height:2px;background:var(--border);margin-top:12px;border-radius:1px">
        <div id="tor-progress-fill" style="height:100%;width:0%;background:var(--accent);transition:width 0.3s"></div>
      </div>
    </div>

    <!-- Tor Error -->
    <div id="screen-tor-error" class="screen">
      <h2>[ TOR NON DISPONIBLE ]</h2>
      <p>BiCrypt nécessite Tor pour fonctionner.<br><br>
      Lance Tor : <code style="color:var(--accent)">sudo systemctl start tor</code><br><br>
      Puis relance l'application.</p>
      <button class="btn-outline" onclick="init()" style="margin-top:24px">Réessayer</button>
    </div>

    <!-- Onboarding -->
    <div id="screen-onboarding" class="screen">
      <div class="logo-block"><span class="logo" style="font-size:32px">BiCrypt</span></div>
      <div class="sub">[ CHOISIS UN PSEUDO ]</div>
      <input id="ob-name" type="text" maxlength="32" placeholder="Pseudo..."
        style="width:100%;background:var(--surface);border:1px solid var(--border);padding:14px 18px;font-size:16px;color:var(--text);font-family:monospace;text-align:center;margin-bottom:16px">
      <div class="tos-row" id="tos-row">
        <div class="checkbox" id="tos-check"></div>
        <span class="tos-text">J'accepte les <span class="tos-link" id="tos-link">Conditions d'utilisation</span></span>
      </div>
      <button class="btn" id="ob-btn" disabled>Continuer</button>
      <p class="note-small" style="margin-top:16px">Clé générée localement — aucune donnée envoyée</p>
    </div>

    <!-- PIN -->
    <div id="screen-pin" class="screen"></div>

    <!-- Home -->
    <div id="screen-home" class="screen"></div>

    <!-- Chat -->
    <div id="screen-chat" class="screen"></div>

    <!-- Identity -->
    <div id="screen-identity" class="screen"></div>

    <!-- Add Contact -->
    <div id="screen-add-contact" class="screen"></div>

    <!-- Channel List -->
    <div id="screen-channel-list" class="screen"></div>

    <!-- Channel Invite -->
    <div id="screen-channel-invite" class="screen"></div>

    <!-- Modal Legal (CGU + Confidentialité, accessible depuis Identité) -->
    <div id="modal-legal" style="display:none" class="modal-overlay">
      <div class="modal-box" style="max-width:560px">
        <div class="modal-title">[ MENTIONS LÉGALES ]</div>
        <div style="display:flex;border-bottom:1px solid var(--border);margin-bottom:0">
          <button class="legal-tab active" data-tab="cgu" style="flex:1;padding:10px;background:none;border:none;border-bottom:2px solid var(--accent);color:var(--accent);font-family:monospace;font-size:11px;font-weight:700;letter-spacing:2px;cursor:pointer">CGU</button>
          <button class="legal-tab" data-tab="privacy" style="flex:1;padding:10px;background:none;border:none;border-bottom:2px solid transparent;color:var(--muted);font-family:monospace;font-size:11px;font-weight:700;letter-spacing:2px;cursor:pointer">CONFIDENTIALITÉ</button>
        </div>
        <div class="modal-scroll" id="legal-content" style="max-height:420px"></div>
        <button class="modal-close" id="legal-close-btn">Fermer</button>
      </div>
    </div>

    <!-- Modal CGU -->
    <div id="modal-tos" style="display:none" class="modal-overlay">
      <div class="modal-box">
        <div class="modal-title">[ CONDITIONS D'UTILISATION ]</div>
        <div class="modal-scroll">
          <div class="tos-clause">01 · Acceptation</div>
          <div class="tos-body">En installant ou utilisant BiCrypt, vous acceptez sans réserve les présentes conditions d'utilisation et la politique de confidentialité.</div>
          <div class="tos-clause">02 · Ce que nous collectons</div>
          <div class="tos-body">BiCrypt ne collecte aucune donnée personnelle. Aucun nom, numéro de téléphone, adresse e-mail ou localisation n'est demandé ni transmis. Votre pseudonyme et votre paire de clés cryptographiques sont générés localement et ne quittent jamais votre appareil en clair.</div>
          <div class="tos-clause">03 · Ce qui transite par le relay</div>
          <div class="tos-body">Le relay (serveur de routage) ne voit que des données chiffrées : identifiants de clés publiques, messages chiffrés E2E (illisibles sans la clé privée), horodatages. Il ne connaît ni votre identité réelle, ni le contenu de vos échanges. La connexion au relay passe exclusivement par le réseau Tor.</div>
          <div class="tos-clause">04 · Stockage local</div>
          <div class="tos-body">Votre clé privée est stockée dans le trousseau sécurisé de votre système d'exploitation (Android Keystore / libsecret Linux). L'historique des messages est chiffré localement. Aucune donnée n'est envoyée à un serveur cloud.</div>
          <div class="tos-clause">05 · Usage légal</div>
          <div class="tos-body">BiCrypt est destiné à la protection légale de la vie privée. Tout usage à des fins illicites (contenu illégal, harcèlement, activités criminelles) est strictement interdit et engage la seule responsabilité de l'utilisateur.</div>
          <div class="tos-clause">06 · Limitation de responsabilité</div>
          <div class="tos-body">L'auteur n'a aucun accès aux clés privées ni aux messages. En cas de perte de clé ou de désinstallation, les données sont irrécupérables. Le logiciel est fourni "tel quel", sans garantie d'infaillibilité.</div>
          <div class="tos-clause">07 · Intégrité des mises à jour</div>
          <div class="tos-body">Toutes les mises à jour sont signées Ed25519 et vérifiées par l'application avant installation. Seule la version officielle distribée sur les canaux officiels est garantie authentique.</div>
          <div class="tos-clause">08 · Propriété intellectuelle</div>
          <div class="tos-body">BiCrypt est un logiciel propriétaire. La décompilation à des fins d'interopérabilité reste autorisée dans les limites de l'article L. 122-6-1 du Code de la Propriété Intellectuelle français.</div>
          <div class="tos-clause">09 · Loi applicable</div>
          <div class="tos-body">Les présentes conditions sont régies par le droit français. En cas de litige, les tribunaux français sont seuls compétents.</div>
        </div>
        <button class="modal-btn" id="tos-accept-btn">J'ACCEPTE</button>
        <button class="modal-close" id="tos-close-btn">Fermer</button>
      </div>
    </div>
  `;

  bindOnboarding();
}

// ── Onboarding ────────────────────────────────────────────────────────────────

function bindOnboarding() {
  let tosAccepted = false;
  const nameInput = document.getElementById('ob-name');
  const btn       = document.getElementById('ob-btn');
  const check     = document.getElementById('tos-check');
  const tosRow    = document.getElementById('tos-row');
  const tosLink   = document.getElementById('tos-link');
  const modal     = document.getElementById('modal-tos');

  // Nom aléatoire
  const names = ['Alice','Bob','Charlie','Diana','Eve','Frank','Grace','Hank','Iris','Jack'];
  nameInput.value = names[Math.floor(Math.random() * names.length)] + Math.floor(Math.random() * 9000 + 1000);

  tosRow.addEventListener('click', e => {
    if (e.target === tosLink) return;
    tosAccepted = !tosAccepted;
    check.classList.toggle('checked', tosAccepted);
    btn.disabled = !tosAccepted;
  });

  tosLink.addEventListener('click', e => {
    e.stopPropagation();
    modal.style.display = 'flex';
  });

  document.getElementById('tos-accept-btn').addEventListener('click', () => {
    tosAccepted = true;
    check.classList.add('checked');
    btn.disabled = false;
    modal.style.display = 'none';
  });
  document.getElementById('tos-close-btn').addEventListener('click', () => {
    modal.style.display = 'none';
  });

  btn.addEventListener('click', async () => {
    const name = nameInput.value.trim();
    if (!name || !tosAccepted) return;
    btn.disabled = true;
    try {
      identity = generateIdentity(name);
      await saveIdentity(identity);
      renderPin('create');
      show('pin');
    } catch (e) {
      toast('Erreur : ' + e.message, 'err');
      btn.disabled = false;
    }
  });
}

// ── PIN ───────────────────────────────────────────────────────────────────────

function renderPin(mode) {
  let pin = '', confirmPin = '', step = 'enter';

  const titles = {
    create_enter:   'Crée ton PIN',
    create_confirm: 'Confirme ton PIN',
    unlock:         'Entre ton PIN',
  };
  const subs = {
    create_enter:   'Choisis un code à 6 chiffres pour protéger l\'app',
    create_confirm: 'Entre le même PIN pour confirmer',
    unlock:         'PIN requis pour accéder à BiCrypt',
  };

  function getKey() { return mode === 'create' ? `${mode}_${step}` : 'unlock'; }

  function render() {
    const cur = step === 'confirm' ? confirmPin : pin;
    document.getElementById('screen-pin').innerHTML = `
      <div class="logo-block" style="margin-bottom:8px;display:flex;align-items:baseline;gap:8px">
        <span class="logo" style="font-size:28px">BiCrypt</span>
        <span style="color:var(--muted);font-size:10px;letter-spacing:1px">v${VERSION}</span>
      </div>
      <h2 style="color:var(--text);font-size:18px;font-weight:700;margin-bottom:8px">${titles[getKey()]}</h2>
      <p style="color:var(--muted);font-size:12px;text-align:center;margin-bottom:40px;line-height:1.5">${subs[getKey()]}</p>
      <div class="pin-dots">
        ${Array.from({length: PIN_LENGTH}).map((_, i) =>
          `<div class="pin-dot ${i < cur.length ? 'filled' : ''}"></div>`
        ).join('')}
      </div>
      <div class="keypad">
        ${['1','2','3','4','5','6','7','8','9','','0','⌫'].map(k => `
          <button class="key ${k === '' ? 'empty' : ''}" data-key="${k}"
            ${k === '' ? 'disabled' : ''}>${k}</button>
        `).join('')}
      </div>
    `;

    function handleKey(k) {
      if (k === '⌫') {
        if (step === 'enter') pin = pin.slice(0, -1);
        else confirmPin = confirmPin.slice(0, -1);
        render();
      } else if (/^[0-9]$/.test(k)) {
        if (step === 'enter' && pin.length < PIN_LENGTH) {
          pin += k;
          if (pin.length === PIN_LENGTH) {
            if (mode === 'create') { step = 'confirm'; render(); }
            else handleUnlock();
          } else render();
        } else if (step === 'confirm' && confirmPin.length < PIN_LENGTH) {
          confirmPin += k;
          if (confirmPin.length === PIN_LENGTH) handleCreate();
          else render();
        }
      }
    }

    document.querySelectorAll('.key:not(.empty)').forEach(btn => {
      btn.addEventListener('click', () => handleKey(btn.dataset.key));
    });

    const onKeydown = (e) => {
      if (currentScreen !== 'pin') { document.removeEventListener('keydown', onKeydown); return; }
      if (e.key === 'Backspace') { e.preventDefault(); handleKey('⌫'); }
      else if (/^[0-9]$/.test(e.key)) handleKey(e.key);
    };
    document.addEventListener('keydown', onKeydown);
  }

  function showPinError(msg) {
    let el = document.getElementById('pin-error');
    if (!el) {
      el = document.createElement('div');
      el.id = 'pin-error';
      el.style.cssText = 'color:var(--danger);font-size:11px;letter-spacing:1px;text-align:center;margin-top:12px;min-height:16px';
      document.getElementById('screen-pin').appendChild(el);
    }
    el.textContent = msg;
  }

  async function handleCreate() {
    if (pin !== confirmPin) {
      pin = ''; confirmPin = ''; step = 'enter';
      render();
      showPinError('PIN différents — recommence');
      return;
    }
    savePinHash(hashPin(pin));
    await launchApp();
  }

  // Comparaison hex en temps constant — évite les timing side-channels.
  function constEq(a, b) {
    if (typeof a !== 'string' || typeof b !== 'string') { return false; }
    if (a.length !== b.length) { return false; }
    let diff = 0;
    for (let i = 0; i < a.length; i++) {
      diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
    }
    return diff === 0;
  }

  async function handleUnlock() {
    let { lockedUntil, attempts } = loadPinLockout();
    if (lockedUntil && Date.now() < lockedUntil) {
      const mins = Math.ceil((lockedUntil - Date.now()) / 60000);
      render();
      showPinError(`Verrouillé — réessaie dans ${mins} min`);
      pin = ''; render(); return;
    }
    // Lockout expiré → on remet le compteur à zéro sinon la première
    // erreur post-lockout re-déclenche immédiatement un verrou (attempts=5→6).
    if (lockedUntil && Date.now() >= lockedUntil) {
      resetPinLockout();
      attempts = 0;
    }

    const stored = loadPinHash();
    if (!stored) { toast('Aucun PIN trouvé', 'err'); return; }

    if (constEq(hashPin(pin), stored)) {
      resetPinLockout();
      await launchApp();
    } else {
      const newAttempts = attempts + 1;
      const remaining = MAX_ATTEMPTS - newAttempts;
      if (remaining <= 0) {
        savePinLockout(newAttempts, Date.now() + LOCKOUT_MS);
        render(); showPinError('Compte verrouillé — 15 min');
      } else {
        savePinLockout(newAttempts, null);
        render(); showPinError(`PIN incorrect — ${remaining} tentative${remaining > 1 ? 's' : ''} restante${remaining > 1 ? 's' : ''}`);
      }
      pin = '';
    }
  }

  render();
}

// ── Home ──────────────────────────────────────────────────────────────────────

function renderHome() {
  const contacts = loadContacts();

  document.getElementById('screen-home').innerHTML = `
    <div class="home-header">
      <div class="header-left" id="logo-tap">
        <div class="header-logo-row">
          <span class="logo" style="font-size:16px">BiCrypt</span>
          <span class="version-badge">v${VERSION}</span>
        </div>
        <span class="header-name">${identity.displayName}
          <span class="header-pubkey">&nbsp;&nbsp;${identity.pubkey.slice(0, 10)}…</span>
        </span>
      </div>
      <div class="header-right">
        <div class="tor-badge ${torStatus}" id="tor-badge">
          <div class="tor-dot"></div>
          <span id="tor-label">${torStatus === 'connected' ? 'Tor' : torStatus === 'connecting' ? 'Connexion...' : 'Hors-ligne'}</span>
        </div>
        <button class="qr-btn" id="btn-identity">QR</button>
      </div>
    </div>

    <div class="list-content">
      <div class="section-header">
        <span class="section-title">Salons</span>
        <span class="section-count add-channel-btn" id="btn-add-channel" style="cursor:pointer;color:var(--accent);font-size:11px;letter-spacing:1px">+ Canal</span>
      </div>
      <div class="row" id="btn-general-channel">
        <div class="avatar avatar-channel">#</div>
        <div class="row-info">
          <span class="row-name">Général</span>
          <span class="row-sub">Canal commun chiffré</span>
        </div>
      </div>
      ${loadChannels().filter(c => c.id !== GENERAL_CHANNEL.id).map(c => `
        <div class="row" data-channel-id="${c.id}">
          <div class="avatar avatar-channel">#</div>
          <div class="row-info">
            <span class="row-name">${escHtml(c.name)}</span>
            <span class="row-sub">${c.type === 'private' ? 'Privé' : 'Public'}</span>
          </div>
        </div>
      `).join('')}

      <div class="section-header" style="margin-top:12px">
        <span class="section-title">Messages privés</span>
        ${contacts.length ? `<span class="section-count">${contacts.length}</span>` : ''}
      </div>
      ${contacts.length ? contacts.map(c => `
        <div class="row" data-contact-id="${c.id}">
          <div class="avatar avatar-contact">${c.displayName.charAt(0).toUpperCase()}</div>
          <div class="row-info">
            <span class="row-name">${escHtml(c.displayName)}</span>
            <span class="row-sub">${c.pubkey.slice(0, 16)}…</span>
          </div>
          <span class="row-badge">E2E</span>
        </div>
      `).join('') : `
        <div class="empty-state">
          <span class="empty-icon">[ – ]</span>
          <span class="empty-text">Aucun contact. Ajoute un pair pour démarrer.</span>
        </div>
      `}
    </div>

    <div class="actions-bar">
      <button class="action-btn action-primary" id="btn-add-contact">+ Contact</button>
      <button class="action-btn action-secondary" id="btn-identity-2">Mon QR</button>
    </div>
  `;

  // Triple-tap nuke (historique uniquement, garde contacts + identity)
  document.getElementById('logo-tap').addEventListener('click', () => {
    tapCount++;
    if (tapTimer) clearTimeout(tapTimer);
    if (tapCount >= 3) {
      tapCount = 0;
      // Modale de confirmation inline
    const overlay = document.createElement('div');
    overlay.style.cssText = 'position:fixed;inset:0;background:#000000cc;display:flex;align-items:center;justify-content:center;z-index:200';
    overlay.innerHTML = `<div style="background:var(--surface);border:1px solid var(--danger);padding:24px;max-width:320px;width:90%">
      <div style="color:var(--danger);font-size:11px;letter-spacing:2px;margin-bottom:16px">[ EFFACER L'HISTORIQUE ]</div>
      <p style="color:var(--muted);font-size:12px;line-height:1.6;margin-bottom:20px">Tout l'historique de messages sera supprimé.<br>Ton compte et tes contacts restent actifs.</p>
      <div style="display:flex;gap:8px">
        <button id="nuke-cancel" style="flex:1;padding:12px;background:transparent;border:1px solid var(--border);color:var(--muted);cursor:pointer;font-family:monospace">Annuler</button>
        <button id="nuke-confirm" style="flex:1;padding:12px;background:var(--danger);border:none;color:#fff;cursor:pointer;font-weight:700;font-family:monospace">Effacer</button>
      </div>
    </div>`;
    document.body.appendChild(overlay);
    overlay.querySelector('#nuke-cancel').onclick = () => overlay.remove();
    overlay.querySelector('#nuke-confirm').onclick = () => { overlay.remove(); nukeHistory(); renderHome(); };
      return;
    }
    tapTimer = setTimeout(() => { tapCount = 0; }, 600);
  });

  const openIdentity = () => { renderIdentity(); show('identity'); };
  document.getElementById('btn-identity').addEventListener('click', openIdentity);
  document.getElementById('btn-identity-2').addEventListener('click', openIdentity);

  document.getElementById('btn-add-contact').addEventListener('click', () => {
    renderAddContact();
    show('add-contact');
  });

  document.getElementById('btn-general-channel').addEventListener('click', () => {
    const ch = loadChannels().find(c => c.id === GENERAL_CHANNEL.id) || { ...GENERAL_CHANNEL };
    openChat('channel', ch);
  });

  document.querySelectorAll('[data-contact-id]').forEach(el => {
    el.addEventListener('click', () => {
      const c = loadContacts().find(x => x.id === el.dataset.contactId);
      if (c) openChat('direct', c);
    });
  });

  document.querySelectorAll('[data-channel-id]').forEach(el => {
    el.addEventListener('click', () => {
      const c = loadChannels().find(x => x.id === el.dataset.channelId);
      if (c) openChat('channel', c);
    });
  });

  document.getElementById('btn-add-channel').addEventListener('click', () => {
    renderChannelList();
    show('channel-list');
  });
}

function updateTorBadge() {
  const badge = document.getElementById('tor-badge');
  const label = document.getElementById('tor-label');
  if (!badge || !label) return;
  badge.className = `tor-badge ${torStatus}`;
  label.textContent = torStatus === 'connected' ? 'Tor' : torStatus === 'connecting' ? 'Connexion...' : 'Hors-ligne';
}

// ── Chat ──────────────────────────────────────────────────────────────────────

function openChat(type, data) {
  currentChat = { type, data };
  renderChat();
  show('chat');
}

function getChatId() {
  if (currentChat.type === 'direct') {
    return [identity.id, currentChat.data.id].sort().join(':');
  }
  return currentChat.data.id;
}

function renderChat() {
  const isChannel = currentChat.type === 'channel';
  const name = isChannel ? `# ${currentChat.data.name}` : currentChat.data.displayName;
  const sub  = isChannel ? (currentChat.data.type === 'private' ? 'Canal privé E2E' : 'Canal public') : null;
  const connected = torStatus === 'connected';

  document.getElementById('screen-chat').innerHTML = `
    <div class="chat-header">
      <button class="back-btn" id="chat-back">←</button>
      <div style="flex:1">
        <div class="chat-name">${name}</div>
        ${sub ? `<div style="color:var(--muted);font-size:11px;margin-top:2px">${sub}</div>` : ''}
      </div>
      ${!isChannel ? '<span class="e2e-badge">E2E</span>' : ''}
    </div>
    ${!connected ? `<div class="offline-banner">Tor déconnecté — messages en attente d'envoi</div>` : ''}
    <div class="messages" id="messages"></div>
    <div class="input-row">
      <textarea class="msg-input" id="msg-input" placeholder="Message..." rows="1" maxlength="4000"></textarea>
      <button class="send-btn" id="send-btn" disabled>↑</button>
    </div>
  `;

  renderMessages();

  document.getElementById('chat-back').addEventListener('click', () => {
    renderHome();
    show('home');
  });

  const input = document.getElementById('msg-input');
  const sendBtn = document.getElementById('send-btn');

  input.addEventListener('input', () => {
    sendBtn.disabled = !input.value.trim();
    input.style.height = 'auto';
    input.style.height = Math.min(input.scrollHeight, 120) + 'px';
  });

  input.addEventListener('keydown', e => {
    if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); sendBtn.click(); }
  });

  sendBtn.addEventListener('click', handleSend);
}

function renderMessages() {
  const el = document.getElementById('messages');
  if (!el) return;
  const msgs = loadMessages(getChatId());

  if (msgs.length === 0) {
    el.innerHTML = `<div style="color:var(--muted);text-align:center;margin-top:80px;font-size:13px;line-height:1.6">
      Début de la conversation chiffrée.<br>Aucun message stocké sur un serveur.
    </div>`;
    return;
  }

  el.innerHTML = msgs.map(m => {
    const isMe = m.from === identity.pubkey;
    const time = new Date(m.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    const status = isMe ? (m.status === 'pending' ? ' ⏳' : ' ✓') : '';
    const senderName = (() => {
      if (isMe || currentChat.type !== 'channel') return null;
      const c = loadContacts().find(x => x.pubkey === m.from);
      return c ? c.displayName : m.from.slice(0, 8) + '…';
    })();
    const fromLabel = senderName
      ? `<div style="color:var(--accent);font-size:11px;margin-bottom:4px">${escHtml(senderName)}</div>` : '';
    return `
      <div class="bubble ${isMe ? 'bubble-me' : 'bubble-them'} ${m.status === 'pending' ? 'bubble-pending' : ''}">
        ${fromLabel}
        <span class="${isMe ? 'bubble-text-me' : 'bubble-text-them'}">${escHtml(m.content)}</span>
        <span class="${isMe ? 'bubble-time-me' : 'bubble-time-them'}" style="font-size:10px;align-self:flex-end">${time}${status}</span>
      </div>
    `;
  }).join('');

  el.scrollTop = el.scrollHeight;
}

async function handleSend() {
  const input = document.getElementById('msg-input');
  const text = input.value.trim();
  if (!text) return;

  const ts = Date.now();
  const connected = torStatus === 'connected';
  const chatId = getChatId();
  const msgId = `${identity.pubkey}:${ts}:local`;

  input.value = '';
  input.style.height = 'auto';
  document.getElementById('send-btn').disabled = true;

  try {
    if (currentChat.type === 'direct') {
      const contact = currentChat.data;
      const { ciphertext, nonce, ephPub, sig } = encryptMessage(text, contact.pubkey, identity.privkey, ts);
      const msg = { id: msgId, from: identity.pubkey, to: contact.pubkey, content: text,
        timestamp: ts, type: 'direct', status: connected ? 'sent' : 'pending', nonce };
      appendMessage(chatId, msg);
      renderMessages();
      if (connected) {
        const ok = await window.bicrypt.relaySend({
          to: contact.pubkey, type: 'direct', ciphertext, nonce, ephPub, sig, timestamp: ts,
        });
        if (!ok) { toast('Envoi échoué — relay non connecté', 'err'); }
      }
    } else {
      const channel = currentChat.data;
      const key = channel.key || derivePublicChannelKey(channel.id);
      const { ciphertext, nonce } = encryptChannelMessage(text, key);
      // Signature v3 : timestamp inclus pour empêcher le replay falsifié.
      const sig = signMessage(`${channel.id}|${ciphertext}|${nonce}|${ts}`, identity.privkey);
      const msg = { id: msgId, from: identity.pubkey, to: channel.id, content: text,
        timestamp: ts, type: 'channel', status: connected ? 'sent' : 'pending', nonce };
      appendMessage(chatId, msg);
      renderMessages();
      if (connected) {
        await window.bicrypt.relaySend({
          to: channel.id, type: 'channel', ciphertext, nonce, sig, timestamp: ts,
        });
      }
    }
  } catch (e) {
    toast('Erreur : ' + (e?.message || e), 'err');
  }
}

// ── Identity ──────────────────────────────────────────────────────────────────

function renderIdentity() {
  const qrData = encodeIdentityQR(identity);
  document.getElementById('screen-identity').innerHTML = `
    <div class="identity-header">
      <button class="back-btn" id="id-back">←</button>
      <span class="identity-title">[ MON IDENTITÉ ]</span>
    </div>
    <div class="identity-content">
      <div class="qr-block">
        <canvas id="qr-canvas" class="qr-canvas" width="200" height="200"></canvas>
        <span class="qr-hint">À faire scanner en personne</span>
      </div>
      <div class="info-block">
        <div class="info-row">
          <span class="info-label">PSEUDO</span>
          <span class="info-value">${identity.displayName}</span>
        </div>
        <div class="info-row">
          <span class="info-label">CLÉ PUBLIQUE</span>
          <span class="info-key" id="pubkey-toggle" title="Cliquer pour voir entière">
            ${identity.pubkey.slice(0, 12)}…${identity.pubkey.slice(-12)}
          </span>
        </div>
        <div class="info-row">
          <span class="info-label">CRÉÉ LE</span>
          <span class="info-value">${new Date(identity.createdAt).toLocaleDateString('fr-FR')}</span>
        </div>
      </div>
      <button class="share-btn" id="id-share">↑  PARTAGER MON ADRESSE</button>
      <p style="color:var(--muted);font-size:11px;text-align:center;line-height:1.6">
        Ce QR ne contient que ta clé publique — rien de sensible.
      </p>
      <button id="id-legal" style="margin-top:4px;background:none;border:none;color:var(--muted);font-family:monospace;font-size:9px;letter-spacing:2px;text-decoration:underline;cursor:pointer;padding:8px">CGU · CONFIDENTIALITÉ</button>
    </div>
  `;

  drawQR(qrData, document.getElementById('qr-canvas'));

  let showFull = false;
  document.getElementById('pubkey-toggle').addEventListener('click', () => {
    showFull = !showFull;
    document.getElementById('pubkey-toggle').textContent = showFull
      ? identity.pubkey
      : `${identity.pubkey.slice(0, 12)}…${identity.pubkey.slice(-12)}`;
  });

  document.getElementById('id-back').addEventListener('click', () => {
    renderHome(); show('home');
  });

  document.getElementById('id-share').addEventListener('click', () => {
    window.bicrypt.clipboardWrite(qrData).then(() => toast('Adresse copiée'));
  });

  document.getElementById('id-legal').addEventListener('click', () => openLegalModal());
}

const CGU_HTML = `
<div style="padding:16px;font-family:monospace">
  <div style="color:var(--text);font-size:14px;font-weight:800;margin-bottom:4px">Conditions Générales d'Utilisation</div>
  <div style="color:var(--muted);font-size:10px;margin-bottom:16px">Version 1.0 · 24 avril 2026</div>
  ${[
    ['1. Propriété Intellectuelle et Licence', 'BiCrypt (code source, code objet, algorithmes obfusqués, interfaces graphiques et logos) est la propriété exclusive de son développeur.<br>· Licence personnelle, non exclusive, non transférable et révocable.<br>· Toute copie, modification, adaptation ou création d\'œuvre dérivée est formellement interdite.<br>· L\'ingénierie inverse, la décompilation, le désassemblage ou toute tentative de contournement des mesures d\'obfuscation sont interdits, sauf dans les limites strictement prévues par la loi applicable.'],
    ['2. Nature du Service', 'BiCrypt est un outil de communication sécurisé utilisant le réseau Tor.<br>· Aucun service d\'hébergement de données : votre identité et vos messages n\'existent que sur votre terminal.<br>· Le développeur met à disposition un relais de transit (.onion) opérant exclusivement en mémoire vive, sans journalisation ni stockage persistant.'],
    ['3. Responsabilité de l\'Utilisateur', '· L\'utilisateur est seul responsable de la sécurité de son terminal et de la conservation de ses accès.<br>· Le développeur n\'a aucun accès aux clés privées ni au code PIN. Aucune récupération n\'est possible en cas de perte.<br>· L\'utilisation de BiCrypt à des fins illicites engage la seule responsabilité de l\'utilisateur et peut entraîner la révocation immédiate de la licence.'],
    ['4. Absence de Garantie (AS IS)', 'Le logiciel est fourni « tel quel », sans garantie d\'aucune sorte.<br>· Bien que le logiciel utilise des primitives cryptographiques éprouvées (X25519, XSalsa20-Poly1305, Ed25519), le développeur ne garantit pas l\'infaillibilité face à des attaques ciblées sur l\'OS ou le matériel.<br>· Le service de relais peut être interrompu pour maintenance ou en raison de l\'instabilité inhérente au réseau Tor, sans préavis ni indemnité.'],
    ['5. Limitation de Responsabilité', 'Dans la mesure permise par la loi, le développeur ne peut être tenu responsable des dommages résultant de :<br>· L\'utilisation ou l\'impossibilité d\'utiliser le logiciel.<br>· L\'accès non autorisé à votre appareil par un tiers.<br>· La perte définitive de données suite à une désinstallation ou une défaillance matérielle.'],
    ['6. Modifications et Résiliation', 'Le développeur se réserve le droit de modifier les présentes conditions ou d\'interrompre le support du logiciel à tout moment. Toute violation de l\'article 1 entraîne la résiliation automatique de votre licence.'],
    ['7. Droit Applicable', 'Les présentes CGU sont régies par le droit français. Tout litige sera porté devant les tribunaux compétents du ressort du siège du développeur.'],
  ].map(([t,b]) => `<div style="margin-top:16px"><div style="color:var(--accent);font-size:10px;font-weight:700;letter-spacing:1px;text-transform:uppercase;margin-bottom:6px">${t}</div><div style="color:var(--text-sub);font-size:12px;line-height:1.7">${b}</div></div>`).join('')}
</div>`;

const PRIVACY_HTML = `
<div style="padding:16px;font-family:monospace">
  <div style="color:var(--text);font-size:14px;font-weight:800;margin-bottom:4px">Politique de Confidentialité</div>
  <div style="color:var(--muted);font-size:10px;margin-bottom:8px">Dernière mise à jour : 27 avril 2026</div>
  <div style="color:var(--text-sub);font-size:12px;line-height:1.7;margin-bottom:8px">BiCrypt est conçu selon le principe du Privacy by Design. Ce que nous ne collectons pas ne peut pas être volé, partagé ou compromis.</div>
  ${[
    ['1. Responsable du traitement', 'Le traitement des données est effectué localement par l\'utilisateur. Le développeur n\'a aucun accès aux données créées ou échangées via l\'application.'],
    ['2. Données stockées sur votre terminal', '· Clés cryptographiques (Ed25519 / X25519) générées localement. La clé privée est protégée par le trousseau sécurisé du système (Android Keystore / libsecret Linux / Keychain macOS / Windows Credential Vault).<br>· Code PIN : jamais stocké en clair. Seul un hash blake2b non réversible est conservé localement.<br>· Contacts (pseudonymes + clés publiques) et messages : chiffrés localement. Seule votre clé privée peut les déchiffrer.'],
    ['3. Transit des données (le Relais)', '· Le relais (.onion) agit comme un commutateur en mémoire vive. Les messages chiffrés y transitent puis sont immédiatement supprimés. Aucune persistance.<br>· Aucun journal de connexion, timestamp ou identifiant n\'est conservé par le relais.<br>· Votre adresse IP réelle n\'est jamais exposée : le relais ne voit que l\'adresse d\'entrée du circuit Tor onion-to-onion.'],
    ['4. Base légale', 'L\'utilisation repose exclusivement sur votre consentement. En générant vos clés, vous initiez le traitement de vos données pour la finalité unique de communication privée.'],
    ['5. Vos droits (RGPD)', '· Accès / portabilité : consultez vos messages et clés dans l\'application.<br>· Effacement : supprimez votre compte depuis l\'écran profil ou désinstallez l\'application. La suppression est définitive — aucune sauvegarde n\'existe côté développeur.'],
    ['6. Sécurité', 'Primitives cryptographiques : X25519 (échange de clés), XSalsa20-Poly1305 (chiffrement des messages), Ed25519 (signatures), blake2b-256 (hash PIN). Le timestamp est inclus dans la signature pour empêcher le replay falsifié. La sécurité dépend également de l\'intégrité de votre propre appareil.'],
    ['7. Transferts internationaux', 'Le réseau Tor implique que les fragments de messages chiffrés transitent par des nœuds intermédiaires Tor répartis dans le monde entier. Ces données sont illisibles pour les tiers et ne permettent pas de vous identifier.'],
    ['8. Bibliothèques tierces et leur fiabilité', 'BiCrypt s\'appuie sur les bibliothèques suivantes, choisies pour leur niveau d\'audit et de maintenance :<br>· <span style="color:var(--accent);font-weight:700">@noble/curves</span> — Ed25519 + X25519. Auteur : Paul Miller. Audit indépendant Cure53 (2023). Pure-JS, sans dépendance native.<br>· <span style="color:var(--accent);font-weight:700">@noble/ciphers</span> — XSalsa20-Poly1305 conforme RFC 7539/8439.<br>· <span style="color:var(--accent);font-weight:700">@noble/hashes</span> — Blake2b et SHA-256 (audit Cure53).<br>· <span style="color:var(--accent);font-weight:700">socket.io-client 4.8</span> — WebSocket sur Tor SOCKS5, lib standard maintenue activement.<br>· <span style="color:var(--accent);font-weight:700">keytar / Android Keystore / libsecret</span> — stockage de la clé privée via le trousseau du système (hardware-backed sur Android compatible).<br>· <span style="color:var(--accent);font-weight:700">Electron 31</span> — version stable, mises à jour de sécurité incluses.<br>· <span style="color:var(--accent);font-weight:700">Tor (binaire embarqué ou socks-proxy-agent)</span> — versions stables uniquement, circuits éphémères, aucun pont par défaut.<br>· Les outils de build (electron-builder, esbuild, javascript-obfuscator) ne sont jamais distribués dans le binaire final livré à l\'utilisateur.'],
    ['9. Mises à jour signées', 'Toute mise à jour est signée Ed25519 avec une clé dédiée distincte des clés utilisateur. Le manifeste signé est servi par le relais .onion, et l\'application refuse toute installation dont la signature ou le SHA-256 ne correspond pas. La clé privée de signature est conservée hors du dépôt et hors de l\'application.'],
    ['10. Contact', 'Pour toute question relative à la protection de vos données : dépôt officiel BiCrypt sur GitHub.'],
  ].map(([t,b]) => `<div style="margin-top:16px"><div style="color:var(--accent);font-size:10px;font-weight:700;letter-spacing:1px;text-transform:uppercase;margin-bottom:6px">${t}</div><div style="color:var(--text-sub);font-size:12px;line-height:1.7">${b}</div></div>`).join('')}
</div>`;

function openLegalModal(defaultTab = 'cgu') {
  const modal = document.getElementById('modal-legal');
  if (!modal) { return; }
  modal.style.display = 'flex';

  function setTab(tab) {
    document.getElementById('legal-content').innerHTML = tab === 'cgu' ? CGU_HTML : PRIVACY_HTML;
    modal.querySelectorAll('.legal-tab').forEach(btn => {
      const active = btn.dataset.tab === tab;
      btn.style.borderBottomColor = active ? 'var(--accent)' : 'transparent';
      btn.style.color = active ? 'var(--accent)' : 'var(--muted)';
    });
  }

  setTab(defaultTab);

  modal.querySelectorAll('.legal-tab').forEach(btn => {
    btn.onclick = () => setTab(btn.dataset.tab);
  });

  document.getElementById('legal-close-btn').onclick = () => { modal.style.display = 'none'; };
  modal.addEventListener('click', e => { if (e.target === modal) modal.style.display = 'none'; }, { once: true });
}

function drawQR(data, canvas) {
  QRCode.toCanvas(canvas, data, {
    width: 200,
    margin: 2,
    color: { dark: '#000000', light: '#ffffff' },
  });
}

// ── Add Contact ───────────────────────────────────────────────────────────────

function renderAddContact() {
  let tab = 'simple';
  const el = document.getElementById('screen-add-contact');

  function render() {
    el.innerHTML = `
      <div class="add-header">
        <span class="add-title">Ajouter un contact</span>
        <button class="cancel-btn" id="add-cancel">Annuler</button>
      </div>
      <div style="display:flex;gap:6px;padding:0 16px;margin-bottom:12px">
        <button class="btn-outline ${tab==='simple'?'active':''}" data-tab="simple" style="flex:1;padding:10px;font-size:11px">Simple</button>
        <button class="btn-outline ${tab==='token'?'active':''}"  data-tab="token"  style="flex:1;padding:10px;font-size:11px">Token</button>
      </div>
      <div class="add-content" id="add-body"></div>
    `;

    document.getElementById('add-cancel').addEventListener('click', () => { renderHome(); show('home'); });
    el.querySelectorAll('[data-tab]').forEach(b => b.onclick = () => { tab = b.dataset.tab; render(); });

    const body = document.getElementById('add-body');

    if (tab === 'simple') {
      body.innerHTML = `
        <p style="color:var(--muted);font-size:12px;line-height:1.6;margin-bottom:12px">
          Colle la clé publique de ton pair (64 caractères hex) et choisis un nom.
        </p>
        <div style="display:flex;gap:8px;margin-bottom:8px">
          <textarea class="paste-input" id="simple-pubkey" placeholder="Clé publique hex (64 chars)..." style="flex:1;min-height:60px;resize:none"></textarea>
          <button class="btn-outline" id="simple-paste" style="align-self:flex-start;padding:10px 14px">Coller</button>
        </div>
        <input id="simple-name" type="text" maxlength="32" placeholder="Nom du contact..."
          style="width:100%;background:var(--surface);border:1px solid var(--border);padding:14px 18px;font-size:15px;color:var(--text);font-family:monospace;margin-bottom:8px">
        <div id="simple-preview" style="color:var(--muted);font-size:12px;min-height:18px;margin-bottom:8px"></div>
        <button class="confirm-btn" id="simple-confirm" style="width:100%" disabled>Ajouter</button>
      `;

      const pkInput   = document.getElementById('simple-pubkey');
      const nameInput = document.getElementById('simple-name');
      const preview   = document.getElementById('simple-preview');
      const btn       = document.getElementById('simple-confirm');

      function checkSimple() {
        const pk   = pkInput.value.trim().toLowerCase();
        const name = nameInput.value.trim();
        if (!pk || !name) { preview.textContent = ''; btn.disabled = true; return; }
        if (!/^[0-9a-f]{64}$/.test(pk)) {
          preview.style.color = 'var(--danger)';
          preview.textContent = '❌ Clé invalide (64 hex requis)';
          btn.disabled = true; return;
        }
        if (pk === identity.pubkey) {
          preview.style.color = 'var(--danger)';
          preview.textContent = "⚠️ C'est ta propre clé";
          btn.disabled = true; return;
        }
        const exists = loadContacts().find(x => x.pubkey === pk);
        preview.style.color = 'var(--accent)';
        preview.textContent = exists ? `↺ Déjà ajouté (${exists.displayName})` : `✓ ${name} (${pk.slice(0,12)}…)`;
        btn.disabled = false;
      }

      pkInput.addEventListener('input', checkSimple);
      nameInput.addEventListener('input', checkSimple);

      document.getElementById('simple-paste').addEventListener('click', async () => {
        try {
          const txt = await window.bicrypt.clipboardRead();
          if (txt) { pkInput.value = txt.trim(); checkSimple(); }
        } catch { toast('Impossible de lire le presse-papiers', 'err'); }
      });

      btn.addEventListener('click', () => {
        const pk   = pkInput.value.trim().toLowerCase();
        const name = nameInput.value.trim();
        if (!/^[0-9a-f]{64}$/.test(pk) || !name) return;
        const contact = { id: pk, pubkey: pk, displayName: name, addedAt: Date.now() };
        addContact(contact);
        renderHome(); show('home');
        openChat('direct', contact);
      });

    } else {
      body.innerHTML = `
        <p style="color:var(--muted);font-size:12px;line-height:1.6;margin-bottom:12px">
          Colle le token d'identité complet (bouton <b>Partager mon adresse</b> dans l'app du pair).
        </p>
        <textarea class="paste-input" id="qr-paste" placeholder='{"v":1,"id":"...","pk":"...","n":"..."}'></textarea>
        <div id="qr-preview" style="color:var(--muted);font-size:12px;min-height:18px;margin-bottom:8px"></div>
        <div style="display:flex;gap:8px">
          <button class="btn-outline" id="add-paste" style="flex:1">Coller</button>
          <button class="confirm-btn" id="add-confirm" style="flex:2" disabled>Ajouter</button>
        </div>
      `;

      const paste   = document.getElementById('qr-paste');
      const btn     = document.getElementById('add-confirm');
      const preview = document.getElementById('qr-preview');

      function checkToken() {
        const val = paste.value.trim();
        if (!val) { preview.textContent = ''; btn.disabled = true; return; }
        const c = decodeIdentityQR(val);
        if (!c) { preview.textContent = '❌ Token invalide'; preview.style.color = 'var(--danger)'; btn.disabled = true; return; }
        if (c.pubkey === identity.pubkey) { preview.textContent = "⚠️ C'est ta propre clé"; preview.style.color = 'var(--danger)'; btn.disabled = true; return; }
        const existing = loadContacts().find(x => x.pubkey === c.pubkey);
        preview.style.color = 'var(--accent)';
        preview.textContent = existing ? `↺ Déjà ajouté : ${c.displayName}` : `✓ ${c.displayName} (${c.pubkey.slice(0,12)}…)`;
        btn.disabled = false;
      }

      paste.addEventListener('input', checkToken);

      document.getElementById('add-paste').addEventListener('click', async () => {
        try {
          const txt = await window.bicrypt.clipboardRead();
          if (txt) { paste.value = txt; checkToken(); }
        } catch { toast('Impossible de lire le presse-papiers', 'err'); }
      });

      btn.addEventListener('click', () => {
        const contact = decodeIdentityQR(paste.value.trim());
        if (!contact) { toast('Token invalide', 'err'); return; }
        if (contact.pubkey === identity.pubkey) { toast("C'est ta propre clé", 'err'); return; }
        addContact(contact);
        renderHome(); show('home');
        openChat('direct', contact);
      });
    }
  }

  render();
}

function renderChannelList() {
  let tab = 'create';
  const el = document.getElementById('screen-channel-list');

  function render() {
    el.innerHTML = `
      <div class="add-header">
        <span class="add-title">Salon</span>
        <button class="cancel-btn" id="cl-back">Retour</button>
      </div>
      <div style="display:flex;gap:6px;padding:0 16px;margin-bottom:12px">
        <button class="btn-outline ${tab==='create'?'active':''}" data-tab="create" style="flex:1;padding:10px;font-size:11px">Créer</button>
        <button class="btn-outline ${tab==='invite'?'active':''}" data-tab="invite" style="flex:1;padding:10px;font-size:11px">Rejoindre</button>
      </div>
      <div class="add-content" id="cl-body"></div>
    `;

    document.getElementById('cl-back').onclick = () => { renderHome(); show('home'); };
    el.querySelectorAll('[data-tab]').forEach(b => b.onclick = () => { tab = b.dataset.tab; render(); });

    const body = document.getElementById('cl-body');
    if (tab === 'create') {
      body.innerHTML = `
        <p style="color:var(--muted);font-size:12px;line-height:1.6;margin-bottom:16px">
          Nouveau canal privé — clé aléatoire, partagée via invitation signée.
        </p>
        <input id="cl-name" type="text" maxlength="48" placeholder="Nom du canal..."
          style="width:100%;background:var(--surface);border:1px solid var(--border);padding:14px 18px;font-size:15px;color:var(--text);font-family:monospace;margin-bottom:12px">
        <button class="confirm-btn" id="cl-create" disabled style="width:100%">Créer</button>
      `;
      const nameIn = document.getElementById('cl-name');
      const btn = document.getElementById('cl-create');
      nameIn.addEventListener('input', () => { btn.disabled = !nameIn.value.trim(); });
      btn.onclick = () => {
        const name = nameIn.value.trim();
        if (!name) return;
        const ch = {
          id: randomChannelId(),
          name,
          type: 'private',
          key: generateChannelKey(),
          createdAt: Date.now(),
          joinedAt: Date.now(),
        };
        addChannel(ch);
        window.bicrypt.relayJoin(ch.id);
        toast('Canal créé');
        renderChannelInvite(ch);
        show('channel-invite');
      };
    } else {
      body.innerHTML = `
        <p style="color:var(--muted);font-size:12px;line-height:1.6;margin-bottom:16px">
          Colle l'invitation signée reçue d'un contact.
        </p>
        <textarea class="paste-input" id="cl-invite" placeholder='{"v":2,"id":"prv:...","name":"...","key":"...","issuer":"...","sig":"..."}'></textarea>
        <div id="cl-invite-preview" style="color:var(--muted);font-size:12px;min-height:18px;margin-bottom:8px"></div>
        <div style="display:flex;gap:8px">
          <button class="btn-outline" id="cl-paste" style="flex:1">Coller</button>
          <button class="confirm-btn" id="cl-join" style="flex:2" disabled>Rejoindre</button>
        </div>
      `;
      const ta = document.getElementById('cl-invite');
      const prev = document.getElementById('cl-invite-preview');
      const joinBtn = document.getElementById('cl-join');
      let pending = null;
      function check() {
        const v = ta.value.trim();
        if (!v) { prev.textContent = ''; joinBtn.disabled = true; pending = null; return; }
        try {
          pending = parseChannelInvite(v);
          if (joinedIds.has(pending.id)) {
            prev.style.color = 'var(--muted)';
            prev.textContent = `↺ Déjà rejoint : ${pending.name}`;
            joinBtn.disabled = true;
          } else {
            prev.style.color = 'var(--accent)';
            prev.textContent = `✓ ${pending.name} · émis par ${pending.issuer ? pending.issuer.slice(0,12)+'…' : 'inconnu'}`;
            joinBtn.disabled = false;
          }
        } catch (e) {
          pending = null;
          prev.style.color = 'var(--danger)';
          prev.textContent = '❌ ' + e.message;
          joinBtn.disabled = true;
        }
      }
      ta.addEventListener('input', check);
      document.getElementById('cl-paste').onclick = async () => {
        try { const t = await window.bicrypt.clipboardRead(); if (t) { ta.value = t; check(); } }
        catch { toast('Impossible de lire le presse-papiers', 'err'); }
      };
      joinBtn.onclick = () => {
        if (!pending) return;
        addChannel(pending);
        window.bicrypt.relayJoin(pending.id);
        toast('Canal rejoint');
        openChat('channel', pending);
      };
    }
  }

  render();
}

function renderChannelInvite(channel) {
  const invite = generateChannelInvite(channel);
  document.getElementById('screen-channel-invite').innerHTML = `
    <div class="add-header">
      <span class="add-title">Invitation · ${escHtml(channel.name)}</span>
      <button class="cancel-btn" id="ci-back">OK</button>
    </div>
    <div class="add-content">
      <p style="color:var(--muted);font-size:12px;line-height:1.6;margin-bottom:12px">
        Envoie ce lien à tes contacts pour qu'ils rejoignent le canal. Signé avec ta clé Ed25519.
      </p>
      <textarea class="paste-input" id="ci-text" readonly style="min-height:140px;font-size:11px">${escHtml(invite)}</textarea>
      <button class="confirm-btn" id="ci-copy" style="width:100%">Copier l'invitation</button>
    </div>
  `;
  document.getElementById('ci-back').onclick = () => { renderHome(); show('home'); };
  document.getElementById('ci-copy').onclick = () => {
    window.bicrypt.clipboardWrite(invite).then(() => toast('Invitation copiée'));
  };
}

// ── Utils ─────────────────────────────────────────────────────────────────────

function escHtml(str) {
  return str.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

let _toastTimer = null;
function toast(msg, type = 'ok') {
  const existing = document.querySelector('.toast');
  if (existing) existing.remove();
  if (_toastTimer) clearTimeout(_toastTimer);
  const el = document.createElement('div');
  el.className = `toast toast-${type}`;
  el.textContent = msg;
  document.body.appendChild(el);
  _toastTimer = setTimeout(() => el.remove(), 2300);
}

// ── Titlebar controls ─────────────────────────────────────────────────────────

(function() {
  document.getElementById('tb-min').onclick   = () => window.bicrypt.winMinimize();
  document.getElementById('tb-max').onclick   = () => window.bicrypt.winMaximize();
  document.getElementById('tb-close').onclick = () => window.bicrypt.winClose();

  const bar = document.getElementById('titlebar');
  let dragging = false, ox = 0, oy = 0;
  bar.addEventListener('mousedown', e => {
    if (e.target.closest('#titlebar-controls')) return;
    dragging = true; ox = e.screenX; oy = e.screenY;
    e.preventDefault();
  });
  document.addEventListener('mousemove', e => {
    if (!dragging) return;
    window.bicrypt.winMove(e.screenX - ox, e.screenY - oy);
    ox = e.screenX; oy = e.screenY;
  });
  document.addEventListener('mouseup', () => { dragging = false; });
})();

// ── Start ─────────────────────────────────────────────────────────────────────

window.init = init;
init();
