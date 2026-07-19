#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MODE="${1:-observe}"
case "$MODE" in baseline|observe|action) ;; *) echo "usage: $0 baseline|observe|action" >&2; exit 2 ;; esac
cd "$ROOT"
mkdir -p integration/reports bench/results

python integration/static_inventory.py --output integration/reports/static-scan.json
python integration/rule_contract.py --output integration/reports/rule-contract.json

if [ "$MODE" = baseline ]; then
  DEFENSECLAW_API_BASE= docker compose up -d --build --force-recreate
else
  : "${DEFENSECLAW_API_BASE:?set DEFENSECLAW_API_BASE in the environment or .env}"
  defenseclaw setup guardrail --mode "$MODE" --restart
  docker compose up -d --build --force-recreate
fi

python bench/benchmark.py run --mode "$MODE" --output "bench/results/$MODE.json"
python integration/attack_chain.py --output integration/reports/attack-chains.json
python integration/report.py
echo "completed AgentRange $MODE run"
