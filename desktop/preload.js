'use strict';

const { contextBridge, ipcRenderer } = require('electron');


// Surface d'API minimale exposée au renderer (contextIsolation + sandbox).
contextBridge.exposeInMainWorld('bicrypt', {
  // Keychain OS
  keychainSet:    (account, value) => ipcRenderer.invoke('keychain-set', account, value),
  keychainGet:    (account)        => ipcRenderer.invoke('keychain-get', account),
  keychainDelete: (account)        => ipcRenderer.invoke('keychain-delete', account),

  // Tor
  torStatus:     ()   => ipcRenderer.invoke('tor-status'),
  onTorProgress: (cb) => ipcRenderer.on('tor-progress', (_e, v) => cb(v)),
  onTorError:    (cb) => ipcRenderer.on('tor-error',    (_e, v) => cb(v)),

  // Relay
  relayConnect:   (pubkey)  => ipcRenderer.invoke('relay-connect', pubkey),
  relaySend:      (payload) => ipcRenderer.invoke('relay-send', payload),
  relayJoin:      (id)      => ipcRenderer.invoke('relay-join', id),
  relayLeave:     (id)      => ipcRenderer.invoke('relay-leave', id),
  relayConnected: ()        => ipcRenderer.invoke('relay-connected'),

  onRelayStatus:   (cb) => ipcRenderer.on('relay-status',  (_e, v) => cb(v)),
  onRelayMessage:  (cb) => ipcRenderer.on('relay-message', (_e, v) => cb(v)),
  offRelayStatus:  (cb) => ipcRenderer.removeListener('relay-status',  cb),
  offRelayMessage: (cb) => ipcRenderer.removeListener('relay-message', cb),

  // Clipboard
  clipboardWrite: (text) => ipcRenderer.invoke('clipboard-write', text),
  clipboardRead:  ()     => ipcRenderer.invoke('clipboard-read'),

  // Contrôles fenêtre (titlebar custom)
  winMinimize: ()       => ipcRenderer.send('win-minimize'),
  winMaximize: ()       => ipcRenderer.send('win-maximize'),
  winClose:    ()       => ipcRenderer.send('win-close'),
  winMove:     (dx, dy) => ipcRenderer.send('win-move', dx, dy),
});
