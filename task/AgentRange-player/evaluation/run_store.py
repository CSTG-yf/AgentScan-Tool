"""Durable, non-overwriting AgentRange evaluation runs.

The run directory belongs to the operator, not the public replay corpus.
Every mode keeps its own observations and metrics so cancellation or a crash
cannot erase evidence from earlier modes.
"""

from __future__ import annotations

import json
import os
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Any
from uuid import uuid4

from metrics import summarize_instances

MODES = ("baseline", "observe", "action")
TERMINAL = {"completed", "failed", "cancelled"}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _atomic_json(path: Path, value: Any) -> None:
    payload = json.dumps(value, ensure_ascii=False, indent=2).encode("utf-8") + b"\n"
    with NamedTemporaryFile(mode="wb", dir=path.parent, prefix=".evaluation-", delete=False) as tmp:
        temporary = Path(tmp.name)
        try:
            tmp.write(payload)
            tmp.flush()
            os.fsync(tmp.fileno())
        except BaseException:
            temporary.unlink(missing_ok=True)
            raise
    try:
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


class EvaluationRun:
    def __init__(self, path: Path):
        self.path = path

    @classmethod
    def create(cls, root: Path, truth: list[dict[str, Any]], baseline: dict[str, Any]) -> "EvaluationRun":
        if not truth:
            raise ValueError("evaluation run requires at least one instance")
        summarize_instances(truth, [])  # validate IDs/labels before creating a run
        root.mkdir(parents=True, exist_ok=True)
        run_id = str(uuid4())
        path = root / run_id
        path.mkdir(mode=0o700)
        run = cls(path)
        # Do not put labels in the corpus or mode artifacts consumed by the
        # target application. Truth stays only in this operator-owned run.
        _atomic_json(path / "truth.json", truth)
        _atomic_json(path / "manifest.json", {
            "schema_version": 1,
            "run_id": run_id,
            "created_at": _now(),
            "updated_at": _now(),
            "status": "prepared",
            "baseline": baseline,
            "modes": {mode: {"status": "pending"} for mode in MODES},
        })
        return run

    def manifest(self) -> dict[str, Any]:
        return _read_json(self.path / "manifest.json")

    def save_corpus(self, public_events: list[dict[str, Any]], trajectories: dict[str, list[dict[str, Any]]]) -> None:
        """Freeze one replay input for all modes without publishing private truth."""
        manifest = self.manifest()
        if manifest["status"] != "prepared" or "corpus" in manifest:
            raise ValueError("corpus can only be frozen once before replay")
        truth = _read_json(self.path / "truth.json")
        ids = [event.get("instance_id") for event in public_events]
        if len(ids) != len(truth) or set(ids) != {item["instance_id"] for item in truth}:
            raise ValueError("public corpus must match private truth instance IDs")
        if len(set(ids)) != len(ids):
            raise ValueError("public corpus contains duplicate instance IDs")
        if any(private in event for event in public_events for private in ("malicious", "kind", "evidence", "trajectory", "label")):
            raise ValueError("public corpus contains private truth or trajectory fields")
        if not set(trajectories).issubset(set(ids)):
            raise ValueError("trajectory contains an unknown instance ID")
        _atomic_json(self.path / "public-corpus.json", public_events)
        _atomic_json(self.path / "trajectories.json", trajectories)
        manifest["corpus"] = {
            "instances": len(ids),
            "public_path": "public-corpus.json",
            "public_sha256": hashlib.sha256((self.path / "public-corpus.json").read_bytes()).hexdigest(),
            "trajectories_path": "trajectories.json",
            "trajectories_sha256": hashlib.sha256((self.path / "trajectories.json").read_bytes()).hexdigest(),
        }
        manifest["updated_at"] = _now()
        _atomic_json(self.path / "manifest.json", manifest)

    def start_mode(self, mode: str) -> None:
        manifest = self.manifest()
        if mode not in MODES or manifest["status"] in TERMINAL:
            raise ValueError("mode or run is not startable")
        index = MODES.index(mode)
        if any(manifest["modes"][previous]["status"] != "completed" for previous in MODES[:index]):
            raise ValueError("previous modes must complete first")
        if manifest["modes"][mode]["status"] != "pending":
            raise ValueError("mode already started")
        manifest["modes"][mode] = {"status": "running", "started_at": _now()}
        manifest["status"] = "running"
        manifest["updated_at"] = _now()
        _atomic_json(self.path / "manifest.json", manifest)

    def complete_mode(self, mode: str, observations: list[dict[str, Any]], evidence: dict[str, Any]) -> dict[str, Any]:
        manifest = self.manifest()
        if mode not in MODES or manifest["modes"][mode]["status"] != "running":
            raise ValueError("mode is not running")
        if "corpus" in manifest and manifest["modes"][mode].get("replay_status") != "completed":
            raise ValueError("frozen corpus replay has not completed")
        truth = _read_json(self.path / "truth.json")
        if len(observations) != len(truth):
            raise ValueError("mode cannot complete while instance observations are missing")
        report = summarize_instances(truth, observations)
        _atomic_json(self.path / f"{mode}-observations.json", observations)
        _atomic_json(self.path / f"{mode}-report.json", {"mode": mode, "summary": report, "evidence": evidence})
        manifest["modes"][mode] = {
            **manifest["modes"][mode], "status": "completed", "finished_at": _now(),
            "observations": f"{mode}-observations.json", "report": f"{mode}-report.json",
        }
        manifest["status"] = "completed" if all(item["status"] == "completed" for item in manifest["modes"].values()) else "running"
        manifest["updated_at"] = _now()
        _atomic_json(self.path / "manifest.json", manifest)
        return report

    def record_replay(self, mode: str, receipt_count: int) -> None:
        manifest = self.manifest()
        if mode not in MODES or manifest["modes"][mode]["status"] != "running":
            raise ValueError("mode is not running")
        if "corpus" not in manifest or receipt_count != manifest["corpus"]["instances"]:
            raise ValueError("replay receipt count does not match frozen corpus")
        manifest["modes"][mode].update({
            "replay_status": "completed",
            "replay_finished_at": _now(),
            "receipt_count": receipt_count,
            "receipts": f"{mode}-receipts.jsonl",
        })
        manifest["updated_at"] = _now()
        _atomic_json(self.path / "manifest.json", manifest)

    def interrupt(self, mode: str, reason: str, *, cancelled: bool = False) -> None:
        manifest = self.manifest()
        if mode not in MODES or manifest["modes"][mode]["status"] != "running":
            raise ValueError("mode is not running")
        status = "cancelled" if cancelled else "failed"
        manifest["modes"][mode] = {**manifest["modes"][mode], "status": status, "finished_at": _now(), "reason": reason[:500]}
        manifest["status"] = status
        manifest["updated_at"] = _now()
        _atomic_json(self.path / "manifest.json", manifest)
