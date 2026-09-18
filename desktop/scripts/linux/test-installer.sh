#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../../.." && pwd)
PACKAGE="$REPO_ROOT/dist/linux/TraceBastion-Desktop-Setup-Linux-x86_64.deb"
test -s "$PACKAGE"
dpkg-deb --info "$PACKAGE" >/dev/null
dpkg-deb --field "$PACKAGE" Depends | grep -q 'fuse3'
LISTING=$(mktemp)
trap 'rm -f "$LISTING"' EXIT
dpkg-deb --contents "$PACKAGE" >"$LISTING"
grep -q 'defenseclaw-desktop' "$LISTING"
grep -q 'README-Linux.md' "$LISTING"

if [ "${TRACEBASTION_INSTALL_SMOKE:-0}" = 1 ]; then
  sudo apt-get install -y "$PACKAGE"
  test -x /usr/bin/defenseclaw-desktop
  sudo /usr/bin/defenseclaw-desktop --install-process-guard
  systemctl is-active --quiet defenseclaw-process-guard.service
  sudo /usr/bin/defenseclaw-desktop --uninstall-process-guard
  sudo apt-get remove -y defenseclaw-desktop
fi

echo "Linux installer smoke test passed"
