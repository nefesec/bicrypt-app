#!/usr/bin/env node
'use strict';

/**
 * Build prod :
 *   1. Bundle+obfuscation renderer (esbuild.js)
 *   2. Backup main.js + preload.js → *.bak (SUR DISQUE, survit à un SIGKILL)
 *   3. Refuse de lancer si main.js/preload.js semblent déjà obfusqués
 *   4. Obfuscation max main.js + preload.js
 *   5. electron-builder --linux + --win
 *   6. Restore main.js + preload.js depuis *.bak (finally, toujours)
 *
 * Résultat : AppImage + .exe NSIS avec JS obfusqué, sources non packagées.
 */

const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');
const JavaScriptObfuscator = require('javascript-obfuscator');

const NODE_FILES = ['main.js', 'preload.js'];

// Obfuscation renforcée — difficile à reverse sans déobfuscateur dédié :
// - controlFlowFlattening : fragmente le flux d'exécution en machine à états
// - deadCodeInjection : injecte du code mort crédible pour noyer l'analyse
// - stringArray RC4 : toutes les strings passent par un décodeur runtime
// - numbersToExpressions : les constantes numériques sont remplacées par des expressions
// - stringArrayRotate/Shuffle : ordre de la table de strings imprévisible
// - selfDefending : résiste au formatage (indentation → comportement brisé)
const NODE_OBF_OPTS = {
  compact: true,
  controlFlowFlattening: true,
  controlFlowFlatteningThreshold: 0.85,
  deadCodeInjection: true,
  deadCodeInjectionThreshold: 0.4,
  stringArray: true,
  stringArrayEncoding: ['rc4'],
  stringArrayThreshold: 1.0,
  stringArrayCallsTransform: true,
  stringArrayCallsTransformThreshold: 1.0,
  stringArrayRotate: true,
  stringArrayShuffle: true,
  stringArrayWrappersCount: 5,
  stringArrayWrappersChainedCalls: true,
  stringArrayWrappersParametersMaxCount: 5,
  stringArrayWrappersType: 'function',
  identifierNamesGenerator: 'hexadecimal',
  identifiersPrefix: '_0bc',
  renameGlobals: false,
  selfDefending: true,
  splitStrings: true,
  splitStringsChunkLength: 5,
  transformObjectKeys: true,
  numbersToExpressions: true,
  shuffleStringArray: true,
  unicodeEscapeSequence: false,
  disableConsoleOutput: false,
  target: 'node',
};

// Heuristique : source obfusquée par javascript-obfuscator → _0x prefix + densité
function looksObfuscated(src) {
  const firstLine = src.split('\n', 2)[0] || '';
  const hasHexVar = /const _0x[0-9a-f]{4,}/.test(firstLine) || /const _0bc[0-9a-f]{4,}/.test(firstLine);
  const density = src.length / (src.split('\n').length || 1);
  return hasHexVar && density > 500;
}

function restore() {
  for (const f of NODE_FILES) {
    const bak = f + '.bak';
    if (fs.existsSync(bak)) {
      fs.copyFileSync(bak, f);
      fs.unlinkSync(bak);
      console.log(`[restore] ${f}`);
    }
  }
}

process.on('SIGINT',  () => { restore(); process.exit(130); });
process.on('SIGTERM', () => { restore(); process.exit(143); });

// Cible : 'linux', 'win', 'all' (défaut: all)
const TARGET = process.argv[2] || 'all';

try {
  for (const f of NODE_FILES) {
    const src = fs.readFileSync(f, 'utf8');
    if (looksObfuscated(src)) {
      throw new Error(`${f} semble déjà obfusqué. Restaure le fichier clean avant de rebuilder.`);
    }
  }

  console.log('[1/3] Bundle+obfuscate renderer...');
  execSync('node esbuild.js', { stdio: 'inherit' });

  console.log('[2/3] Obfuscate main.js + preload.js (mode renforcé)...');
  for (const f of NODE_FILES) {
    const src = fs.readFileSync(f, 'utf8');
    fs.writeFileSync(f + '.bak', src);
    const obf = JavaScriptObfuscator.obfuscate(src, NODE_OBF_OPTS);
    fs.writeFileSync(f, obf.getObfuscatedCode());
    console.log(`[obfuscate] ${f} → ${(fs.statSync(f).size / 1024).toFixed(0)} KB`);
  }

  console.log('[3/3] electron-builder...');
  if (TARGET === 'linux') {
    execSync('npx electron-builder --linux', { stdio: 'inherit' });
  } else if (TARGET === 'win') {
    execSync('npx electron-builder --win', { stdio: 'inherit' });
  } else {
    execSync('npx electron-builder --linux --win', { stdio: 'inherit' });
  }

  const distDir = path.join(__dirname, 'dist');
  const pkg = JSON.parse(fs.readFileSync(path.join(__dirname, 'package.json'), 'utf8'));
  const v = pkg.version;

  const toClean = ['linux-unpacked', 'win-unpacked', 'builder-debug.yml', 'builder-effective-config.yaml'];
  for (const name of toClean) {
    try { fs.rmSync(path.join(distDir, name), { recursive: true, force: true }); } catch (_) {}
  }

  // Supprime les anciens artefacts
  try {
    for (const f of fs.readdirSync(distDir)) {
      const keep = [`BiCrypt-${v}.AppImage`, `BiCrypt Setup ${v}.exe`, `BiCrypt Setup ${v}.exe.blockmap`];
      if ((f.endsWith('.AppImage') || f.endsWith('.exe') || f.endsWith('.blockmap')) && !keep.includes(f)) {
        fs.unlinkSync(path.join(distDir, f));
        console.log(`[clean] Supprimé : ${f}`);
      }
    }
  } catch (_) {}

  console.log(`[✓] Build terminé — v${v}`);
  try {
    for (const f of fs.readdirSync(distDir)) {
      if (f.endsWith('.AppImage') || f.endsWith('.exe')) {
        const size = (fs.statSync(path.join(distDir, f)).size / 1024 / 1024).toFixed(1);
        console.log(`  ${f} (${size} MB)`);
      }
    }
  } catch (_) {}
} catch (e) {
  console.error('[✗] Build échoué:', e.message);
  process.exitCode = 1;
} finally {
  restore();
}
