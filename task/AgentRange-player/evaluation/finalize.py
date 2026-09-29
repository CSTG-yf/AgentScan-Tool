"""Merge independently collected evidence into one mode's instance results."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

from run_store import EvaluationRun, MODES, _read_json


def _by_id(rows: list[dict[str, Any]], expected: set[str], label: str) -> dict[str, dict[str, Any]]:
    by_id = {str(row.get("instance_id") or ""): row for row in rows}
    if set(by_id) != expected or len(by_id) != len(rows):
        raise ValueError(f"{label} does not match frozen truth instances")
    return by_id


def _validate_fields(rows: dict[str, dict[str, Any]], allowed: set[str], label: str) -> None:
    for row in rows.values():
        if set(row) - allowed:
            raise ValueError(f"{label} contains unsupported fields")


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def finalize_mode(run_path: Path, mode: str) -> dict[str, Any]:
    run = EvaluationRun(run_path)
    manifest = run.manifest()
    if mode not in MODES or manifest["modes"][mode].get("replay_status") != "completed":
        raise ValueError("mode replay must complete before finalization")
    truth = _read_json(run.path / "truth.json")
    expected = {item["instance_id"] for item in truth}
    detections_path = run.path / f"{mode}-detection-observations.json"
    effects_path = run.path / f"{mode}-effect-observations.json"
    receipts_path = run.path / f"{mode}-receipts.jsonl"
    detection = _by_id(_read_json(detections_path), expected, "detection observations")
    effects = _by_id(_read_json(effects_path), expected, "effect observations")
    _validate_fields(detection, {"instance_id", "detected", "evidence_refs", "detection_scope_complete"}, "detection observations")
    _validate_fields(effects, {"instance_id", "effect", "effect_evidence_ref"}, "effect observations")
    receipts = [json.loads(line) for line in receipts_path.read_text(encoding="utf-8").splitlines()]
    receipts_by_id = _by_id(receipts, expected, "replay receipts")
    if any(item.get("status") not in ("completed", "http_error") for item in receipts_by_id.values()):
        raise ValueError("infrastructure replay failure cannot be finalized")
    observations = []
    for item in truth:
        instance_id = item["instance_id"]
        observations.append({
            "instance_id": instance_id,
            "detected": detection[instance_id].get("detected"),
            "evidence_refs": detection[instance_id].get("evidence_refs", []),
            "detection_scope_complete": detection[instance_id].get("detection_scope_complete") is True,
            "effect": effects[instance_id].get("effect", "unknown"),
            "effect_evidence_ref": effects[instance_id].get("effect_evidence_ref"),
            # No enforced_block or business_completed here. Those require
            # authoritative response and business-state evidence, not HTTP.
        })
    evidence = {
        "replay_receipts": {"path": receipts_path.name, "sha256": _sha256(receipts_path)},
        "detection_observations": {"path": detections_path.name, "sha256": _sha256(detections_path)},
        "effect_observations": {"path": effects_path.name, "sha256": _sha256(effects_path)},
        "limitations": [
            "negative detection windows are not verified",
            "enforced blocks require response-action evidence",
            "normal business success requires business-state evidence",
        ],
    }
    return run.complete_mode(mode, observations, evidence)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run_path", type=Path)
    parser.add_argument("mode", choices=MODES)
    args = parser.parse_args()
    report = finalize_mode(args.run_path, args.mode)
    print(json.dumps(report["coverage"], ensure_ascii=False))


if __name__ == "__main__":
    main()
