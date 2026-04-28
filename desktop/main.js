'use strict';

const { app, BrowserWindow, clipboard, ipcMain, nativeTheme, session, shell } = require('electron');
const path  = require('path');
const fs    = require('fs');
const net   = require('net');
const { spawn } = require('child_process');
const { io }    = require('socket.io-client');
const { SocksClient } = require('socks');

nativeTheme.themeSource = 'dark';

// GPU flags conditionnels par platform :
//
// LINUX : `disable-gpu` est nécessaire car certains compositors (Wayland,
// pilotes nouveau, VirtualBox, X11 + GPU intégré) provoquent un rendu noir
// avec l'accélération matérielle activée. C'est un bug Electron connu.
//
// WINDOWS : NE JAMAIS `disable-gpu`. Sur Windows, l'accélération hardware
// est attendue par le compositor DWM. Désactiver le GPU = écran noir, rendu
// très lent, ou perte de l'affichage selon le pilote graphique.
// On garde uniquement `disable-gpu-sandbox` pour éviter les problèmes de
// permissions du sandbox GPU (qui causent parfois des écrans noirs sur
// certaines configs Windows avec antivirus).
//
// MACOS : pas de switch nécessaire, Metal fonctionne nativement.
if (process.platform === 'linux') {
  app.commandLine.appendSwitch('disable-gpu');
} else if (process.platform === 'win32') {
  // disable-gpu-sandbox uniquement : règle les écrans noirs causés par les AV
  // qui bloquent le sandbox du process GPU. Ne pas confondre avec --no-sandbox
  // qui désactiverait la sécurité du renderer.
  app.commandLine.appendSwitch('disable-gpu-sandbox');
}

// ── Tor embarqué ──────────────────────────────────────────────────────────────

// Port SOCKS5 actif — soit le port d'un Tor lancé par BiCrypt (19052),
// soit un Tor Browser/tor.exe externe détecté (9150/9050).
const TOR_SOCKS_PORT_EMBEDDED = 19052;
let activeSocksPort           = TOR_SOCKS_PORT_EMBEDDED;
const TOR_DATA_DIR            = path.join(app.getPath('userData'), 'tor-data');

let torProcess  = null;
let torReady    = false;
let torProgress = 0;
let mainWindow  = null;

function findTorBinary() {
  const isWin = process.platform === 'win32';
  const exe = isWin ? 'tor.exe' : 'tor';

  // 1. Binaire bundlé avec l'app (resourcesPath/bin/tor[.exe])
  const bundled = path.join(process.resourcesPath || __dirname, 'bin', exe);
  if (fs.existsSync(bundled)) { return bundled; }

  // 2. Chemins standards par OS
  const candidates = [];
  if (isWin) {
    const env = process.env;
    // Tor Browser installé pour cet utilisateur
    if (env.APPDATA) {
      candidates.push(path.join(env.APPDATA, 'Tor Browser', 'Browser', 'TorBrowser', 'Tor', 'tor.exe'));
    }
    if (env.LOCALAPPDATA) {
      candidates.push(path.join(env.LOCALAPPDATA, 'Tor Browser', 'Browser', 'TorBrowser', 'Tor', 'tor.exe'));
      candidates.push(path.join(env.LOCALAPPDATA, 'Programs', 'Tor Browser', 'Browser', 'TorBrowser', 'Tor', 'tor.exe'));
    }
    // Installations communes
    candidates.push('C:\\Tor\\tor.exe');
    candidates.push('C:\\Program Files\\Tor Browser\\Browser\\TorBrowser\\Tor\\tor.exe');
    candidates.push('C:\\Program Files (x86)\\Tor Browser\\Browser\\TorBrowser\\Tor\\tor.exe');
  } else if (process.platform === 'darwin') {
    candidates.push('/Applications/Tor Browser.app/Contents/MacOS/Tor/tor');
    candidates.push('/usr/local/bin/tor');
    candidates.push('/opt/homebrew/bin/tor');
  } else {
    // Linux/BSD
    candidates.push('/usr/sbin/tor', '/usr/bin/tor', '/usr/local/bin/tor');
  }

  for (const p of candidates) {
    try { if (fs.existsSync(p)) { return p; } } catch (_) {}
  }
  return null;
}

// Détecte un SOCKS5 Tor déjà ouvert en local (Tor Browser ou tor.exe lancé
// par l'utilisateur). Permet à BiCrypt de fonctionner sur Windows sans
// embarquer de binaire Tor. Sondage rapide sur les ports standards.
const EXTERNAL_TOR_PORTS = [
  9150,  // Tor Browser default
  9050,  // tor.exe daemon default
];

function probePort(host, port, timeoutMs = 800) {
  return new Promise(resolve => {
    const s = net.createConnection(port, host);
    let done = false;
    const finish = (ok) => { if (done) return; done = true; try { s.destroy(); } catch (_) {} resolve(ok); };
    s.on('connect', () => finish(true));
    s.on('error',   () => finish(false));
    setTimeout(() => finish(false), timeoutMs);
  });
}

async function findExternalTorSocks() {
  for (const port of EXTERNAL_TOR_PORTS) {
    if (await probePort('127.0.0.1', port)) { return port; }
  }
  return null;
}

function isPortBusy(port) {
  return new Promise(resolve => {
    const s = net.createConnection(port, '127.0.0.1');
    s.on('connect', () => { s.destroy(); resolve(true);  });
    s.on('error',   () => {             resolve(false); });
    setTimeout(() => { s.destroy(); resolve(false); }, 1000);
  });
}

async function startTor() {
  if (torReady) { return; }

  // 1. Si BiCrypt a déjà lancé Tor sur 19052 (lancement précédent), le réutilise
  if (await isPortBusy(TOR_SOCKS_PORT_EMBEDDED)) {
    activeSocksPort = TOR_SOCKS_PORT_EMBEDDED;
    torReady = true;
    torProgress = 100;
    return;
  }

  // 2. Cherche un Tor Browser/tor.exe déjà ouvert (9150/9050) — pratique sur
  // Windows si l'utilisateur a Tor Browser installé.
  const externalPort = await findExternalTorSocks();
  if (externalPort) {
    console.log('[tor] SOCKS5 externe détecté sur', externalPort);
    activeSocksPort = externalPort;
    torReady = true;
    torProgress = 100;
    return;
  }

  // 3. Tente de spawner notre propre tor.exe / tor
  const torBinary = findTorBinary();
  if (!torBinary) {
    const hint = process.platform === 'win32'
      ? 'Lance Tor Browser ou installe tor.exe pour utiliser BiCrypt.'
      : 'Installe Tor : sudo apt install tor';
    throw new Error(`Tor introuvable. ${hint}`);
  }

  const lockFile = path.join(TOR_DATA_DIR, 'lock');
  if (fs.existsSync(lockFile)) { try { fs.unlinkSync(lockFile); } catch (_) {} }

  fs.mkdirSync(TOR_DATA_DIR, { recursive: true, mode: 0o700 });

  const torrcPath = path.join(TOR_DATA_DIR, 'torrc');
  fs.writeFileSync(torrcPath,
    `SocksPort ${TOR_SOCKS_PORT_EMBEDDED}\nDataDirectory ${TOR_DATA_DIR}\nLog notice stderr\n`,
    { mode: 0o600 }
  );

  activeSocksPort = TOR_SOCKS_PORT_EMBEDDED;

  return new Promise((resolve, reject) => {
    const args = ['-f', torrcPath, '--RunAsDaemon', '0'];
    torProcess = spawn(torBinary, args, { stdio: ['ignore', 'pipe', 'pipe'] });

    const sendTorProgress = (p) => {
      if (mainWindow && !mainWindow.isDestroyed() && !mainWindow.webContents.isDestroyed()) {
        mainWindow.webContents.send('tor-progress', p);
      }
    };

    const onLine = chunk => {
      const m = chunk.toString().match(/Bootstrapped (\d+)%/);
      if (m) {
        torProgress = parseInt(m[1], 10);
        sendTorProgress(torProgress);
        if (torProgress >= 100) { torReady = true; resolve(); }
      }
    };

    torProcess.stdout.on('data', onLine);
    torProcess.stderr.on('data', onLine);
    torProcess.on('error', err => reject(err));
    torProcess.on('exit', code => {
      torReady = false;
      if (code !== 0 && code !== null) { sendTorProgress(-1); }
    });

    setTimeout(() => {
      if (!torReady) { reject(new Error('Tor bootstrap timeout (120s)')); }
    }, 120_000);
  });
}

function stopTor() {
  if (proxyServer) { proxyServer.close(); proxyServer = null; }
  if (torProcess) {
    torProcess.kill('SIGTERM');
    torProcess = null;
    torReady = false;
  }
}

// ── Fenêtre principale ────────────────────────────────────────────────────────

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 420,
    height: 780,
    minWidth: 360,
    minHeight: 600,
    backgroundColor: '#000000',
    frame: false,
    // show:false + ready-to-show évite le flash blanc/noir au démarrage,
    // particulièrement visible sur Windows où DWM peut afficher la fenêtre
    // une fraction de seconde avant que le HTML soit rendu.
    show: false,
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      nodeIntegrationInWorker: false,
      nodeIntegrationInSubFrames: false,
      sandbox: true,
      webSecurity: true,
      allowRunningInsecureContent: false,
      experimentalFeatures: false,
      spellcheck: false,
      webviewTag: false,
    },
  });

  mainWindow.loadFile(path.join(__dirname, 'renderer', 'index.html'));

  // Affiche la fenêtre uniquement quand le contenu est prêt à être peint.
  // Fallback 1.5s au cas où ready-to-show n'est jamais émis (bug rare GPU).
  let shown = false;
  const showOnce = () => { if (shown) return; shown = true; mainWindow?.show(); };
  mainWindow.once('ready-to-show', showOnce);
  setTimeout(showOnce, 1500);

  // Bloque navigation / redirect / nouvelles fenêtres
  mainWindow.webContents.on('will-navigate',       (e) => e.preventDefault());
  mainWindow.webContents.on('will-redirect',       (e) => e.preventDefault());
  mainWindow.webContents.on('will-frame-navigate', (e) => e.preventDefault());
  mainWindow.webContents.setWindowOpenHandler(() => ({ action: 'deny' }));

  // DevTools bloqués en prod
  if (app.isPackaged) {
    mainWindow.webContents.on('devtools-opened', () => mainWindow.webContents.closeDevTools());
    mainWindow.webContents.on('before-input-event', (event, input) => {
      const k = input.key?.toLowerCase();
      if (input.control && input.shift && (k === 'i' || k === 'j' || k === 'c')) { event.preventDefault(); }
      if (k === 'f12') { event.preventDefault(); }
      if (input.control && k === 'r') { event.preventDefault(); }
    });
  }
}

// Permissions : tout refuser (pas de mic/cam/notif/geoloc/etc)
app.on('ready', () => {
  session.defaultSession.setPermissionRequestHandler((_wc, _perm, cb) => cb(false));
  session.defaultSession.setPermissionCheckHandler(() => false);
});

// Empêche webview, nouvelles fenêtres et permissions sur tous les webContents
app.on('web-contents-created', (_e, contents) => {
  contents.on('will-attach-webview', (event) => event.preventDefault());
  contents.setWindowOpenHandler(() => ({ action: 'deny' }));
});

app.whenReady().then(() => {
  createWindow();
  mainWindow.webContents.on('did-finish-load', () => {
    const safeSend = (ch, data) => {
      if (mainWindow && !mainWindow.isDestroyed() && !mainWindow.webContents.isDestroyed()) {
        mainWindow.webContents.send(ch, data);
      }
    };
    startTor()
      .then(() => safeSend('tor-progress', 100))
      .catch(err => safeSend('tor-error', err.message));
  });
});

function stopRelay() {
  if (socket) {
    socket.removeAllListeners();
    socket.disconnect();
    socket = null;
  }
}

app.on('window-all-closed', () => {
  stopRelay();
  stopTor();
  if (process.platform !== 'darwin') { app.quit(); }
});

app.on('before-quit', () => { stopRelay(); stopTor(); });

// ── IPC : Keychain (validation stricte) ──────────────────────────────────────

const SERVICE = 'BiCrypt';
const ACCOUNT_RE = /^(privkey:[0-9a-f]{32}|biometric_gate|local-storage-key)$/;
const VALUE_MAX = 4096;

function isValidAccount(a) { return typeof a === 'string' && ACCOUNT_RE.test(a); }
function isValidValue(v)   { return typeof v === 'string' && v.length > 0 && v.length <= VALUE_MAX; }

ipcMain.handle('keychain-set', async (_e, account, value) => {
  if (!isValidAccount(account) || !isValidValue(value)) { return false; }
  try { const k = require('keytar'); await k.setPassword(SERVICE, account, value); return true; }
  catch { return false; }
});

ipcMain.handle('keychain-get', async (_e, account) => {
  if (!isValidAccount(account)) { return null; }
  try { const k = require('keytar'); return await k.getPassword(SERVICE, account); }
  catch { return null; }
});

ipcMain.handle('keychain-delete', async (_e, account) => {
  if (!isValidAccount(account)) { return false; }
  try { const k = require('keytar'); await k.deletePassword(SERVICE, account); return true; }
  catch { return false; }
});

// ── IPC : Clipboard ───────────────────────────────────────────────────────────

ipcMain.handle('clipboard-write', (_e, text) => {
  if (typeof text !== 'string' || text.length > 8192) return false;
  clipboard.writeText(text);
  return true;
});

ipcMain.handle('clipboard-read', () => clipboard.readText());

// ── IPC : Tor status ──────────────────────────────────────────────────────────

ipcMain.handle('tor-status', () => ({ ready: torReady, progress: torProgress }));

// ── IPC : Relay via tunnel TCP local → SOCKS5 Tor → .onion ───────────────────

const ONION      = '5ag466cldjw3lc4okg5suw5fgp32evcccud44u2gfuyh6pvxykz73gqd.onion';
const ONION_PORT = 4000;
const PUBKEY_RE  = /^[0-9a-f]{64}$/i;
const CHANNEL_MAX = 256;

let socket      = null;
let proxyServer = null;
let proxyPort   = null;
const joinedChannels = new Set();

async function startLocalTorProxy() {
  if (proxyServer) { return proxyPort; }

  return new Promise((resolve, reject) => {
    proxyServer = net.createServer((client) => {
      SocksClient.createConnection({
        proxy:       { host: '127.0.0.1', port: activeSocksPort, type: 5 },
        command:     'connect',
        destination: { host: ONION, port: ONION_PORT },
      }).then(({ socket: remote }) => {
        client.pipe(remote);
        remote.pipe(client);
        const cleanup = () => { client.destroy(); remote.destroy(); };
        client.on('error', cleanup);
        remote.on('error', cleanup);
        client.on('close', () => remote.destroy());
        remote.on('close', () => client.destroy());
      }).catch(err => {
        console.error('[proxy] SOCKS error:', err.message);
        client.destroy();
      });
    });

    // 127.0.0.1 only — jamais exposé au LAN
    proxyServer.listen(0, '127.0.0.1', () => {
      proxyPort = proxyServer.address().port;
      console.log('[proxy] tunnel local port', proxyPort, '→', ONION);
      resolve(proxyPort);
    });

    proxyServer.on('error', reject);
  });
}

ipcMain.handle('relay-connect', async (_e, pubkey) => {
  if (typeof pubkey !== 'string' || !PUBKEY_RE.test(pubkey)) { return false; }
  if (socket?.connected) { return true; }

  const port = await startLocalTorProxy();
  const RELAY_TOKEN = '58f5e9784b893259db90b552323c5b54898254fb4c6e81d629d2684c2c580f5f';

  socket = io(`http://127.0.0.1:${port}`, {
    auth: { pubkey, token: RELAY_TOKEN },
    transports: ['websocket'],
    reconnection: true,
    reconnectionDelay: 3000,
    reconnectionDelayMax: 30000,
    reconnectionAttempts: Infinity,
    timeout: 120000,
  });

  const send = (channel, data) => {
    if (mainWindow && !mainWindow.isDestroyed() && !mainWindow.webContents.isDestroyed()) {
      mainWindow.webContents.send(channel, data);
    }
  };

  socket.on('connect', () => {
    console.log('[relay] connecté via tunnel local:', port);
    joinedChannels.forEach(id => socket.emit('join_channel', { channelId: id }));
    send('relay-status', 'connected');
  });
  socket.on('disconnect',    (reason) => { console.log('[relay] déconnecté:', reason); send('relay-status', 'disconnected'); });
  socket.on('connect_error', (err)    => { console.error('[relay] connect_error:', err.message); send('relay-status', 'error'); });
  socket.on('message', payload => {
    console.log('[relay] message entrant type=%s from=%s', payload?.type, String(payload?.from).slice(0, 12));
    send('relay-message', payload);
  });

  return true;
});

ipcMain.handle('relay-send', (_e, payload) => {
  if (!socket?.connected) { return false; }
  if (!payload || typeof payload !== 'object') { return false; }
  socket.emit('message', payload);
  return true;
});

ipcMain.handle('relay-join', (_e, channelId) => {
  if (typeof channelId !== 'string' || channelId.length === 0 || channelId.length > CHANNEL_MAX) { return; }
  joinedChannels.add(channelId);
  if (socket?.connected) { socket.emit('join_channel', { channelId }); }
});

ipcMain.handle('relay-leave', (_e, channelId) => {
  if (typeof channelId !== 'string' || channelId.length === 0 || channelId.length > CHANNEL_MAX) { return; }
  joinedChannels.delete(channelId);
  if (socket?.connected) { socket.emit('leave_channel', { channelId }); }
});

ipcMain.handle('relay-connected', () => socket?.connected ?? false);

// ── IPC : contrôles fenêtre (custom titlebar) ─────────────────────────────────

ipcMain.on('win-minimize', () => mainWindow?.minimize());
ipcMain.on('win-maximize', () => {
  if (mainWindow?.isMaximized()) { mainWindow.unmaximize(); }
  else { mainWindow?.maximize(); }
});
ipcMain.on('win-close', () => mainWindow?.close());

// Drag custom — clamp les deltas pour bloquer une attaque hypothétique
// qui enverrait des valeurs énormes depuis un renderer compromis.
ipcMain.on('win-move', (_e, dx, dy) => {
  if (!mainWindow || mainWindow.isMaximized()) { return; }
  if (typeof dx !== 'number' || typeof dy !== 'number') { return; }
  if (!Number.isFinite(dx) || !Number.isFinite(dy)) { return; }
  const cdx = Math.max(-200, Math.min(200, dx));
  const cdy = Math.max(-200, Math.min(200, dy));
  const [x, y] = mainWindow.getPosition();
  mainWindow.setPosition(x + cdx, y + cdy);
});
