'use strict';

// Bundle + obfusque UNIQUEMENT le renderer.
// L'obfuscation de main.js/preload.js est faite par build-prod.js (script séparé
// qui backup/obfusque/restaure pour ne pas casser le dev).

const esbuild = require('esbuild');
const fs      = require('fs');
const JavaScriptObfuscator = require('javascript-obfuscator');

const DEV = process.env.BICRYPT_DEV === '1';
const OUT = 'renderer/bundle.js';

esbuild.buildSync({
  entryPoints: ['renderer/app.js'],
  bundle:      true,
  outfile:     OUT,
  platform:    'browser',
  format:      'iife',
  target:      ['chrome120'],
  minify:      !DEV,
  legalComments: 'none',
  sourcemap:   false,
  drop:        DEV ? [] : ['console', 'debugger'],
  define:      { '__DEV__': 'false' },
});

console.log(`[esbuild] ${DEV ? 'dev' : 'prod'} OK → ${OUT}`);

if (!DEV) {
  const src = fs.readFileSync(OUT, 'utf8');
  const obf = JavaScriptObfuscator.obfuscate(src, {
    compact: true,
    controlFlowFlattening: true,
    controlFlowFlatteningThreshold: 0.6,
    deadCodeInjection: true,
    deadCodeInjectionThreshold: 0.2,
    stringArray: true,
    stringArrayEncoding: ['base64'],
    stringArrayThreshold: 0.75,
    identifierNamesGenerator: 'hexadecimal',
    renameGlobals: false,
    selfDefending: true,
    splitStrings: true,
    splitStringsChunkLength: 6,
    transformObjectKeys: true,
    unicodeEscapeSequence: false,
    disableConsoleOutput: true,
    target: 'browser',
  });
  fs.writeFileSync(OUT, obf.getObfuscatedCode());
  console.log(`[obfuscate] renderer → ${(fs.statSync(OUT).size / 1024).toFixed(0)} KB`);
}
