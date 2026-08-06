"""Portable verifier for the generic AgentRange runtime-rule contract."""

from __future__ import annotations

import argparse
import json
import re
import time
from pathlib import Path

import yaml


def matches(rule: dict, value) -> bool:
    if rule["kind"] == "regex":
        return bool(re.search(rule["pattern"], str(value)))
    if rule["kind"] == "tenant_scope":
        allowed = str(value.get("principal_tenant") or "")
        requested = str(value.get("requested_tenant") or "")
        return bool(allowed and requested and (requested == "*" or requested != allowed))
    raise ValueError(f"unknown rule kind: {rule['kind']}")


def verify(path: Path) -> dict:
    contract = yaml.safe_load(path.read_text(encoding="utf-8"))
    limit = float(contract["performance_limit_ms_per_case"])
    results = []
    for rule in contract["rules"]:
        started = time.perf_counter()
        attack_match = matches(rule, rule["attack"])
        benign_matches = [matches(rule, item) for item in rule["benign"]]
        elapsed_ms = (time.perf_counter() - started) * 1000 / (1 + len(rule["benign"]))
        results.append(
            {
                "rule_id": rule["id"],
                "attack_match": attack_match,
                "benign_matches": benign_matches,
                "elapsed_ms_per_case": round(elapsed_ms, 6),
                "passed": attack_match and not any(benign_matches) and elapsed_ms <= limit,
            }
        )
    return {"passed": all(item["passed"] for item in results), "limit_ms_per_case": limit, "results": results}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rules", type=Path, default=Path(__file__).with_name("runtime_rules.yaml"))
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    report = verify(args.rules)
    rendered = json.dumps(report, ensure_ascii=False, indent=2)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    print(rendered)
    return 0 if report["passed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
