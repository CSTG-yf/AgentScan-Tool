"""Replay a frozen evaluation corpus and durably record per-instance HTTP receipts.

This does not mark a mode complete: detection, side-effect, environment-reset and
resource evidence must be collected and verified separately.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from pathlib import Path

RANGE_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(RANGE_ROOT / "scenario-runner"))

from runner import clear_trajectories, inject_trajectories, replay_events  # noqa: E402
from run_store import EvaluationRun, MODES  # noqa: E402


def _verified_json(run: EvaluationRun, filename: str, expected_hash: str):
    path = run.path / filename
    content = path.read_bytes()
    if hashlib.sha256(content).hexdigest() != expected_hash:
        raise ValueError(f"frozen {filename} hash mismatch")
    return json.loads(content)


def replay_mode(run_path: Path, mode: str) -> int:
    run = EvaluationRun(run_path)
    manifest = run.manifest()
    if mode not in MODES or "corpus" not in manifest:
        raise ValueError("mode or frozen corpus is missing")
    corpus = manifest["corpus"]
    public = _verified_json(run, corpus["public_path"], corpus["public_sha256"])
    trajectories = _verified_json(run, corpus["trajectories_path"], corpus["trajectories_sha256"])
    if len(public) != corpus["instances"]:
        raise ValueError("frozen corpus instance count mismatch")
    run.start_mode(mode)
    receipts_path = run.path / f"{mode}-receipts.jsonl"
    receipt_count = 0
    try:
        with receipts_path.open("x", encoding="utf-8") as output:
            def save_receipt(receipt: dict) -> None:
                nonlocal receipt_count
                output.write(json.dumps(receipt, ensure_ascii=False) + "\n")
                output.flush()
                os.fsync(output.fileno())
                receipt_count += 1

            try:
                inject_trajectories(trajectories)
                replay_events(public, receipt_sink=save_receipt)
            finally:
                clear_trajectories()
        run.record_replay(mode, receipt_count)
        return receipt_count
    except BaseException as exc:
        run.interrupt(mode, f"replay failed: {type(exc).__name__}", cancelled=isinstance(exc, KeyboardInterrupt))
        raise


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run_path", type=Path)
    parser.add_argument("mode", choices=MODES)
    args = parser.parse_args()
    print(f"Recorded {replay_mode(args.run_path, args.mode)} instance receipts")


if __name__ == "__main__":
    main()
