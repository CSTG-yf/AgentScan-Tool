#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
DESKTOP_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)
REPO_ROOT=$(CDPATH= cd -- "$DESKTOP_ROOT/.." && pwd)
RESOURCE_DIR="$DESKTOP_ROOT/src-tauri/resources"

command -v python3 >/dev/null 2>&1 || { echo "python3 is required" >&2; exit 1; }
mkdir -p "$RESOURCE_DIR"
python3 -m PyInstaller --noconfirm --clean --onefile \
  --name tracebastion-sandbox \
  --paths "$REPO_ROOT/cli" \
  --hidden-import ai_sandbox.seccomp \
  --distpath "$RESOURCE_DIR" \
  --workpath "$DESKTOP_ROOT/.sandbox-build/work" \
  --specpath "$DESKTOP_ROOT/.sandbox-build" \
  "$DESKTOP_ROOT/scripts/sandbox_sidecar.py"
chmod 0755 "$RESOURCE_DIR/tracebastion-sandbox"
"$RESOURCE_DIR/tracebastion-sandbox" --help >/dev/null
