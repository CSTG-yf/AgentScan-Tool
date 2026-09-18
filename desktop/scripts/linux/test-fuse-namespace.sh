#!/usr/bin/env bash
set -euo pipefail

binary="${1:-desktop/src-tauri/target/debug/defenseclaw-desktop}"
workspace="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
binary="$(realpath "$binary")"
runtime="$(mktemp -d /tmp/tracebastion-fuse-test.XXXXXX)"
trap 'rm -rf "$runtime"' EXIT

secret="$runtime/secret.txt"
policy="$runtime/policy.json"
printf 'host-secret-content' > "$secret"

cd "$workspace"
POLICY_PATH="$policy" SECRET_PATH="$secret" node - <<'NODE'
const fs = require("fs");
const policy = JSON.parse(fs.readFileSync("desktop/contracts/process-guard.default.json", "utf8"));
policy.fileGuard = {
  enabled: true,
  auditRoots: [process.env.SECRET_PATH],
  blacklist: [{
    id: "fuse-namespace-e2e",
    enabled: true,
    path: process.env.SECRET_PATH,
    matchKind: "exact",
    access: ["read"],
    action: "returnEmptyContent",
    description: "FUSE namespace end-to-end test"
  }]
};
fs.writeFileSync(process.env.POLICY_PATH, JSON.stringify(policy, null, 2));
NODE

"$binary" --run-controlled-agent "$policy" /bin/sh -c '
  test "$TRACEBASTION_CONTROLLED" = 1
  test "$TRACEBASTION_FILE_GUARD" = fuse-namespace
  test ! -s "$1"
  test -z "$(cat "$1")"
' sh "$secret"

test "$(cat "$secret")" = "host-secret-content"
printf 'FUSE namespace end-to-end test passed\n'
