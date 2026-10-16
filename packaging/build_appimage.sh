#!/usr/bin/env bash
# Build a fully self-contained Linux AppImage of the Toshiba CIX Manager.
#
# The AppImage bundles its own CPython (from astral-sh/python-build-standalone),
# so the target machine needs nothing installed — double-click and go.
#
#   bash packaging/build_appimage.sh
#   -> dist/Toshiba_CIX_Manager-x86_64.AppImage   (git-ignored)
#
# Designed to run in CI (ubuntu). No FUSE needed (APPIMAGE_EXTRACT_AND_RUN=1).
set -euo pipefail

HERE="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"
ROOT="$(dirname "$HERE")"
ARCH="${ARCH:-x86_64}"
WORK="$ROOT/build/appimage"
APPDIR="$WORK/AppDir"
DIST="$ROOT/dist"
export APPIMAGE_EXTRACT_AND_RUN=1

echo "==> clean"
rm -rf "$WORK"
mkdir -p "$APPDIR/usr/share/toshiba-cix-manager" "$DIST"

echo "==> resolve a standalone CPython 3.12 (${ARCH})"
PBS_JSON="$(curl -fsSL https://api.github.com/repos/astral-sh/python-build-standalone/releases/latest)"
PBS_URL="$(printf '%s' "$PBS_JSON" | python3 -c "
import json,sys,re
rel=json.load(sys.stdin)
pat=re.compile(r'cpython-3\.12\.\d+\+.*-${ARCH}-unknown-linux-gnu-install_only\.tar\.gz$')
for a in rel['assets']:
    if pat.search(a['name']) and 'install_only' in a['name'] and a['name'].endswith('.tar.gz'):
        print(a['browser_download_url']); break
")"
if [ -z "${PBS_URL:-}" ]; then
  echo "could not find a 3.12 install_only build for ${ARCH}" >&2; exit 1
fi
echo "    $PBS_URL"
curl -fsSL "$PBS_URL" -o "$WORK/python.tar.gz"
mkdir -p "$APPDIR/usr"
tar -xzf "$WORK/python.tar.gz" -C "$APPDIR/usr"   # extracts to AppDir/usr/python

echo "==> copy app"
cp -r "$ROOT/toshiba_cix" "$APPDIR/usr/share/toshiba-cix-manager/"
cp "$ROOT/app.py" "$APPDIR/usr/share/toshiba-cix-manager/"

echo "==> bundle certifi (CA bundle for the self-updater's TLS)"
# python-build-standalone sets its default CA verify paths to the BUILD machine,
# so ssl.create_default_context() can find no CAs on the user's box and the
# in-app updater fails with CERTIFICATE_VERIFY_FAILED. update.py falls back to a
# system bundle and then to certifi.where(); install certifi here so that last
# resort always resolves, even on a minimal host. (Build-time only; the engine
# stays pure stdlib — certifi is only a CA data file.)
"$APPDIR/usr/python/bin/python3" -m pip install --no-warn-script-location certifi

echo "==> icon + desktop"
python3 "$HERE/make_icon.py"
cp "$HERE/icon.png" "$APPDIR/toshiba-cix-manager.png"
cp "$HERE/icon.png" "$APPDIR/.DirIcon"
cp "$HERE/toshiba-cix-manager.desktop" "$APPDIR/toshiba-cix-manager.desktop"
mkdir -p "$APPDIR/usr/share/applications" "$APPDIR/usr/share/icons/hicolor/256x256/apps"
cp "$HERE/toshiba-cix-manager.desktop" "$APPDIR/usr/share/applications/"
cp "$HERE/icon.png" "$APPDIR/usr/share/icons/hicolor/256x256/apps/toshiba-cix-manager.png"

echo "==> AppRun"
cat > "$APPDIR/AppRun" <<'EOF'
#!/bin/bash
HERE="$(dirname "$(readlink -f "$0")")"
export PATH="$HERE/usr/python/bin:$PATH"
exec "$HERE/usr/python/bin/python3" \
     "$HERE/usr/share/toshiba-cix-manager/app.py" "$@"
EOF
chmod +x "$APPDIR/AppRun"

echo "==> fetch appimagetool"
curl -fsSL \
  "https://github.com/AppImage/appimagetool/releases/download/continuous/appimagetool-${ARCH}.AppImage" \
  -o "$WORK/appimagetool"
chmod +x "$WORK/appimagetool"

echo "==> build AppImage"
OUT="$DIST/Toshiba_CIX_Manager-${ARCH}.AppImage"
"$WORK/appimagetool" "$APPDIR" "$OUT"
echo "Built: $OUT"
