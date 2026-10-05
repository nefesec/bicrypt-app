#!/usr/bin/env bash
# Regénère releases/latest.json depuis la dernière release GitHub.
# (release.sh de l'app l'écrit déjà à chaque publication : ce script sert
# uniquement à le reconstruire à la main en cas de besoin.)
#
# Usage : ./scripts/gen-latest.sh
# Nécessite : gh (authentifié), jq

set -euo pipefail

REPO="nefesec/bicrypt-app"
SITE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$SITE_DIR/releases/latest.json"

LATEST=$(gh api "repos/$REPO/releases/latest")
VERSION=$(jq -r '.tag_name' <<<"$LATEST")
APK=$(jq -c '[.assets[] | select(.name | endswith(".apk"))][0] // empty' <<<"$LATEST")
[ -n "$APK" ] || { echo "Aucun APK dans la release $VERSION" >&2; exit 1; }

# L'empreinte vient du fichier .sha256 publié avec la release (même source que release.sh).
SHA_URL=$(jq -r '[.assets[] | select(.name | endswith(".sha256"))][0].browser_download_url // empty' <<<"$LATEST")
SHA=""
[ -n "$SHA_URL" ] && SHA=$(curl -fsSL "$SHA_URL" | awk '{print $1}')
[[ "$SHA" =~ ^[a-f0-9]{64}$ ]] || { echo "Empreinte SHA-256 introuvable ou invalide" >&2; exit 1; }

jq -n --arg v "$VERSION" --arg sha "$SHA" --argjson a "$APK" '
  {version: $v,
   apk: {version: $v, filename: $a.name, size: $a.size, sha256: $sha,
         url: $a.browser_download_url}}' > "$OUT"

echo "→ $OUT"
cat "$OUT"
