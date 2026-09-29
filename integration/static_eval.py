"""Score static inventory against a frozen, separately curated local fixture."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_RANGE_ROOT = ROOT / "task" / "AgentRange-player-full"
DEFAULT_OUTPUT = ROOT / "integration" / "reports" / "static-scan.json"
DEFAULT_TRUTH = ROOT / "integration" / "agentrange_contracts" / "static-ground-truth.yaml"
DEFAULT_RESULT = ROOT / "integration" / "reports" / "static-eval.json"


def _metrics(expected: set, predicted: set) -> dict:
    tp = len(expected & predicted)
    fp = len(predicted - expected)
    fn = len(expected - predicted)
    return {
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "precision": tp / (tp + fp) if tp + fp else None,
        "recall": tp / (tp + fn) if tp + fn else None,
        "miss_rate": fn / len(expected) if expected else None,
    }


def evaluate(scan_path: Path, truth_path: Path, arena_root: Path) -> dict:
    from hashlib import sha256

    scan = json.loads(scan_path.read_text(encoding="utf-8"))
    truth = yaml.safe_load(truth_path.read_text(encoding="utf-8"))
    digest = sha256()
    for path in sorted(item for item in arena_root.rglob("*") if item.is_file() and "__pycache__" not in item.parts):
        digest.update(path.relative_to(arena_root).as_posix().encode("utf-8"))
        digest.update(sha256(path.read_bytes()).hexdigest().encode("ascii"))
    actual_hash = digest.hexdigest()
    if actual_hash != truth["arena_sha256"]:
        raise ValueError(f"arena hash differs from static ground truth: {actual_hash}")
    if Path(scan["range_root"]).resolve() != arena_root.resolve():
        raise ValueError("scan and ground truth refer to different arena roots")

    expected_assets = set(truth["asset_ids"])
    predicted_assets = {row["id"] for row in scan["assets"]}
    expected_risks = {tuple(row) for row in truth["risk_pairs"]}
    predicted_risks = {(row["rule_id"], row["asset_id"]) for row in scan["findings"]}
    assets = _metrics(expected_assets, predicted_assets)
    risks = _metrics(expected_risks, predicted_risks)
    return {
        "schema_version": 1,
        "scope": "local_frozen_fixture",
        "arena_sha256": actual_hash,
        "asset": {**assets, "missed": sorted(expected_assets - predicted_assets), "unexpected": sorted(predicted_assets - expected_assets)},
        "risk": {
            **risks,
            "missed": sorted([list(row) for row in expected_risks - predicted_risks]),
            "unexpected": sorted([list(row) for row in predicted_risks - expected_risks]),
        },
        "acceptance": {
            "asset_miss_rate_lt_0_05": assets["miss_rate"] is not None and assets["miss_rate"] < 0.05,
            "asset_precision_gte_0_99": assets["precision"] is not None and assets["precision"] >= 0.99,
            "risk_recall_gte_0_95": risks["recall"] is not None and risks["recall"] >= 0.95,
            "risk_precision_gte_0_95": risks["precision"] is not None and risks["precision"] >= 0.95,
            "risk_miss_rate_lt_0_05": risks["miss_rate"] is not None and risks["miss_rate"] < 0.05,
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scan", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--truth", type=Path, default=DEFAULT_TRUTH)
    parser.add_argument("--arena-root", type=Path, default=DEFAULT_RANGE_ROOT)
    parser.add_argument("--output", type=Path, default=DEFAULT_RESULT)
    args = parser.parse_args()
    result = evaluate(args.scan.resolve(), args.truth.resolve(), args.arena_root.resolve())
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if all(result["acceptance"].values()) else 2


if __name__ == "__main__":
    raise SystemExit(main())
