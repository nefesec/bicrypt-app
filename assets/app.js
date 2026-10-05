/* BiCrypt — script de la page d'accueil.
 *
 * Sécurité :
 *  - aucune requête vers un tiers : seuls status.json et releases/latest.json,
 *    servis par ce site, sont lus (l'API GitHub n'est plus contactée, elle
 *    recevait l'IP de chaque visiteur) ;
 *  - aucun innerHTML : uniquement textContent (compatible Trusted Types) ;
 *  - le lien de téléchargement n'est accepté que s'il pointe exactement vers
 *    une release officielle nefesec/bicrypt-app sur github.com.
 * Sans JavaScript, les boutons mènent à la page de la dernière release GitHub.
 */
'use strict';

(function () {
  var FALLBACK_URL = 'https://github.com/nefesec/bicrypt-app/releases/latest';
  var APK_URL_RE = /^https:\/\/github\.com\/nefesec\/bicrypt-app\/releases\/download\/v[0-9][0-9A-Za-z.\-]{0,30}\/bicrypt-[0-9A-Za-z.\-]{1,40}\.apk$/;
  var SHA256_RE = /^[a-f0-9]{64}$/i;
  var VERSION_RE = /^v?[0-9]{1,4}(\.[0-9]{1,4}){0,3}$/;

  function all(sel) { return Array.prototype.slice.call(document.querySelectorAll(sel)); }
  function setText(sel, text) { all(sel).forEach(function (el) { el.textContent = text; }); }
  function groupHex(hex) { return hex.toUpperCase().match(/.{1,4}/g).join(' '); }
  function formatSize(bytes) { return (bytes / 1048576).toFixed(1).replace('.', ',') + ' Mo'; }

  function getJSON(path) {
    return fetch(path, { cache: 'no-store', credentials: 'omit', redirect: 'error' })
      .then(function (res) {
        if (!res.ok) { throw new Error(path + ' : HTTP ' + res.status); }
        var type = res.headers.get('content-type') || '';
        if (type.indexOf('application/json') === -1) { throw new Error(path + ' : type ' + type); }
        return res.json();
      });
  }

  // ── Release ──────────────────────────────────────────────────────────────
  function applyRelease(m) {
    if (!m || typeof m !== 'object' || !m.apk || typeof m.apk !== 'object') { throw new Error('manifeste invalide'); }
    var version = String(m.apk.version || m.version || '');
    var url = m.apk.url;
    var size = Number(m.apk.size);
    var sha = String(m.apk.sha256 || '');

    if (!VERSION_RE.test(version)) { throw new Error('version invalide'); }
    if (typeof url !== 'string' || !APK_URL_RE.test(url)) { throw new Error('URL refusée'); }

    all('[data-dl]').forEach(function (a) {
      a.href = url;
      a.rel = 'noopener noreferrer';
    });
    setText('[data-version]', version.replace(/^v?/, 'v'));
    if (isFinite(size) && size > 0 && size < 500 * 1048576) { setText('[data-size]', formatSize(size)); }

    if (SHA256_RE.test(sha)) {
      setText('[data-sha]', groupHex(sha));
      all('[data-copy="sha"]').forEach(function (b) { b.dataset.value = sha.toLowerCase(); b.hidden = false; });
    } else {
      setText('[data-sha]', 'Non disponible — compare avec la page GitHub de la version.');
    }
  }

  function releaseFailed() {
    all('[data-dl]').forEach(function (a) { a.href = FALLBACK_URL; });
    setText('[data-version]', 'dernière version');
    setText('[data-size]', '≈ 33 Mo');
    setText('[data-sha]', 'Indisponible ici — affichée sur la page GitHub de la version.');
    all('[data-dl-error]').forEach(function (el) { el.hidden = false; });
  }

  // ── Maintenance ──────────────────────────────────────────────────────────
  function showMaintenance(s) {
    var box = document.getElementById('maintenance');
    if (!box) { return; }
    if (typeof s.title === 'string' && s.title) { setText('[data-m-title]', s.title.slice(0, 100)); }
    if (typeof s.message === 'string' && s.message) { setText('[data-m-msg]', s.message.slice(0, 500)); }
    all('[data-dl-block]').forEach(function (el) { el.hidden = true; });
    box.hidden = false;

    var until = s.until ? new Date(s.until).getTime() : NaN;
    if (!isFinite(until)) { return; }
    function tick() {
      var diff = until - Date.now();
      if (diff <= 0) { setText('[data-m-until]', 'Réouverture imminente : recharge la page.'); return; }
      var h = Math.floor(diff / 3600000);
      var m = Math.floor((diff % 3600000) / 60000);
      setText('[data-m-until]', 'Réouverture prévue dans ' + h + ' h ' + String(m).padStart(2, '0') + ' min');
    }
    tick();
    setInterval(tick, 30000);
  }

  // ── Copier ───────────────────────────────────────────────────────────────
  function selectText(el) {
    var range = document.createRange();
    range.selectNodeContents(el);
    var sel = window.getSelection();
    sel.removeAllRanges();
    sel.addRange(range);
  }

  all('[data-copy]').forEach(function (btn) {
    var label = btn.textContent;
    btn.addEventListener('click', function () {
      var value = btn.dataset.value || '';
      var target = document.getElementById(btn.getAttribute('aria-controls'));
      function done(text) {
        btn.textContent = text;
        btn.classList.add('done');
        setTimeout(function () { btn.textContent = label; btn.classList.remove('done'); }, 1800);
      }
      if (value && navigator.clipboard && window.isSecureContext) {
        navigator.clipboard.writeText(value).then(function () { done('Copié'); }, function () {
          if (target) { selectText(target); done('Sélectionné'); }
        });
      } else if (target) {
        selectText(target);
        done('Sélectionné');
      }
    });
  });

  // ── Démarrage ────────────────────────────────────────────────────────────
  getJSON('/status.json')
    .catch(function () { return null; })
    .then(function (status) {
      if (status && status.maintenance === true) { return showMaintenance(status); }
      return getJSON('/releases/latest.json').then(applyRelease);
    })
    .catch(releaseFailed);
})();
