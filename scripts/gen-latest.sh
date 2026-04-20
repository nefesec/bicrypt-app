#!/usr/bin/env bash
# Regénère releases/latest.json depuis les GitHub releases.
# Prend toujours la dernière release pour l'APK, et la dernière release
# contenant un AppImage pour le desktop (fallback si le build Electron
# a été skippé pour cette version).
#
# Usage : ./scripts/gen-latest.sh
# Nécessite : gh (authentifié), jq

set -euo pipefail

REPO="nefesec/bicrypt-app"
SITE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$SITE_DIR/releases/latest.json"

# Dernière release globale
LATEST=$(gh api "repos/$REPO/releases/latest")

# APK : dans la dernière release
APK=$(jq -r '.assets[] | select(.name | endswith(".apk"))' <<<"$LATEST")
APK_VERSION=$(jq -r '.tag_name' <<<"$LATEST")

# AppImage : cherche dans les releases récentes (fallback si dernière sans AppImage)
APPIMAGE=""
APPIMAGE_VERSION=""
for tag in $(gh api "repos/$REPO/releases" --jq '.[].tag_name' | head -10); do
  CANDIDATE=$(gh api "repos/$REPO/releases/tags/$tag" \
    --jq '.assets[] | select(.name | endswith(".AppImage"))' 2>/dev/null || echo "")
  if [ -n "$CANDIDATE" ]; then
    APPIMAGE="$CANDIDATE"
    APPIMAGE_VERSION="$tag"
    break
  fi
done

build_entry() {
  local asset="$1" version="$2"
  [ -z "$asset" ] && { echo "null"; return; }
  local name size url digest downloads
  name=$(jq -r '.name' <<<"$asset")
  size=$(jq -r '.size' <<<"$asset")
  url=$(jq -r '.browser_download_url' <<<"$asset")
  digest=$(jq -r '.digest // ""' <<<"$asset" | sed 's/^sha256://')
  downloads=$(jq -r '.download_count' <<<"$asset")
  jq -n --arg v "$version" --arg f "$name" --arg sha "$digest" \
        --arg url "$url" --argjson sz "$size" --argjson dl "$downloads" \
        '{version:$v, filename:$f, size:$sz, sha256:$sha, url:$url, downloads:$dl}'
}

APK_JSON=$(build_entry "$APK" "$APK_VERSION")
APPIMAGE_JSON=$(build_entry "$APPIMAGE" "$APPIMAGE_VERSION")

jq -n --arg v "$APK_VERSION" --argjson apk "$APK_JSON" --argjson ai "$APPIMAGE_JSON" \
  '{version:$v, apk:$apk, appimage:$ai}' > "$OUT"

echo "→ $OUT"
cat "$OUT"
