#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
DESKTOP_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)
REPO_ROOT=$(CDPATH= cd -- "$DESKTOP_ROOT/.." && pwd)
RESOURCE_DIR="$DESKTOP_ROOT/src-tauri/resources"
ARTIFACT_DIR="$REPO_ROOT/dist/linux"

for command in pnpm cargo go; do
  command -v "$command" >/dev/null 2>&1 || { echo "$command is required" >&2; exit 1; }
done

mkdir -p "$RESOURCE_DIR" "$ARTIFACT_DIR"
cd "$REPO_ROOT"
go build -buildvcs=false -trimpath -ldflags '-s -w' -o "$RESOURCE_DIR/defenseclaw-gateway" ./cmd/defenseclaw
chmod 0755 "$RESOURCE_DIR/defenseclaw-gateway"

cd "$DESKTOP_ROOT"
if [ "${SKIP_INSTALL:-0}" != 1 ]; then
  pnpm install --frozen-lockfile
fi
pnpm tauri build --config src-tauri/tauri.linux.conf.json --bundles deb,appimage

find src-tauri/target/release/bundle -type f \( -name '*.deb' -o -name '*.AppImage' \) -print0 |
  while IFS= read -r -d '' artifact; do
    case "$artifact" in
      *.deb) destination="$ARTIFACT_DIR/TraceBastion-Desktop-Setup-Linux-x86_64.deb" ;;
      *.AppImage) destination="$ARTIFACT_DIR/TraceBastion-Desktop-Setup-Linux-x86_64.AppImage" ;;
    esac
    cp "$artifact" "$destination"
    [ "${destination##*.}" != AppImage ] || chmod 0755 "$destination"
    echo "Installer: $destination"
  done

test -s "$ARTIFACT_DIR/TraceBastion-Desktop-Setup-Linux-x86_64.deb"
test -s "$ARTIFACT_DIR/TraceBastion-Desktop-Setup-Linux-x86_64.AppImage"
