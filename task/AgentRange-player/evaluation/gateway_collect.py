"""Collect real Gateway detections for one replay mode without inventing negatives."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
from typing import Any

import httpx

from run_store import EvaluationRun, MODES, _atomic_json, _read_json


def detection_observations(truth: list[dict[str, Any]], detections: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_session: dict[str, list[str]] = {}
    for item in detections:
        session = str(item.get("session_id") or "")
        detection_id = str(item.get("detection_id") or "")
        if session and detection_id:
            by_session.setdefault(session, []).append(detection_id)
    return [{
        "instance_id": item["instance_id"],
        "detected": True if by_session.get(item["instance_id"]) else None,
        "evidence_refs": [f"detection:{id}" for id in by_session.get(item["instance_id"], [])],
        "detection_scope_complete": False,
    } for item in truth]


def collect_detections(run_path: Path, mode: str, *, base_url: str = "http://127.0.0.1:18970", token: str | None = None) -> list[dict[str, Any]]:
    run = EvaluationRun(run_path)
    manifest = run.manifest()
    if mode not in MODES or manifest["modes"][mode].get("replay_status") != "completed":
        raise ValueError("mode replay must complete before detection collection")
    token = token or os.environ.get("DEFENSECLAW_GATEWAY_TOKEN")
    if not token:
        raise ValueError("DEFENSECLAW_GATEWAY_TOKEN is required")
    started_at = manifest["modes"][mode]["started_at"]
    detections: list[dict[str, Any]] = []
    with httpx.Client(timeout=20, trust_env=False, headers={"Authorization": f"Bearer {token}"}) as client:
        offset = 0
        while True:
            response = client.get(f"{base_url.rstrip('/')}/api/v1/runtime-detections", params={
                "start_time": started_at, "limit": 1000, "offset": offset,
            })
            response.raise_for_status()
            payload = response.json()
            items = payload.get("items")
            total = payload.get("total")
            if not isinstance(items, list) or not isinstance(total, int) or total < 0:
                raise ValueError("invalid Gateway detection page")
            detections.extend(items)
            offset += len(items)
            if offset >= total:
                break
            if not items:
                raise ValueError("Gateway detection pagination stopped before total")
    ids = [item.get("detection_id") for item in detections]
    if len(ids) != len(set(ids)) or any(not item for item in ids):
        raise ValueError("Gateway returned duplicate or empty detection IDs")
    truth = _read_json(run.path / "truth.json")
    observations = detection_observations(truth, detections)
    _atomic_json(run.path / f"{mode}-gateway-detections.json", {
        "start_time": started_at,
        "base_url": base_url.rstrip("/"),
        "count": len(detections),
        "items": detections,
    })
    _atomic_json(run.path / f"{mode}-detection-observations.json", observations)
    return observations


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run_path", type=Path)
    parser.add_argument("mode", choices=MODES)
    parser.add_argument("--gateway-base", default="http://127.0.0.1:18970")
    args = parser.parse_args()
    print(f"Collected {len(collect_detections(args.run_path, args.mode, base_url=args.gateway_base))} instance observations")


if __name__ == "__main__":
    main()
