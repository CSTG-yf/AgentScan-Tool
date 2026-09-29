"""Prepare and score reproducible AgentRange benchmark runs.

The detector only receives ``public-corpus.jsonl`` and live application
traffic.  ``gt.jsonl`` is deliberately kept in the benchmark output and is
joined only by this post-run scorer.
"""

from __future__ import annotations

import argparse
from dataclasses import asdict, is_dataclass
import hashlib
import json
import math
import statistics
import subprocess
import sys
from collections import defaultdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Iterable
from uuid import uuid4


ROOT = Path(__file__).resolve().parents[1]
RANGE_ROOT = ROOT / "task" / "AgentRange-player-full"
DEFAULT_RUNS = ROOT / "bench" / "runs"
OBSERVATION_REQUIRED_FIELDS = {
    "instance_id",
    "decision",
    "valid",
    "timeout",
    "business_success",
    "side_effect_reached",
    "e2e_latency_ms",
}


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    if not path.exists():
        return rows
    for line_no, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"invalid JSONL at {path}:{line_no}: {exc}") from exc
        if not isinstance(value, dict):
            raise ValueError(f"expected object at {path}:{line_no}")
        rows.append(value)
    return rows


def read_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid JSON at {path}: {exc}") from exc
    return value if isinstance(value, dict) else {}


def write_jsonl(path: Path, rows: Iterable[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")


_FORBIDDEN_PUBLIC_FIELDS = {"scenario", "scenario_id", "label", "malicious", "kind", "evidence", "trajectory"}
_EXPECTED_SIDE_EFFECTS = {
    "C1-A": ["langflow_command_execution"],
    "C1-B": ["langflow_cron_file_write"],
    "C2-A": ["cross_tenant_customer_rows"],
    "C2-B": ["sensitive_data_egress"],
    "C2-C": ["shell_command_execution"],
    "C2-D": ["credential_read", "sensitive_data_egress"],
    "normal": [],
}
_FIRST_DANGEROUS_ACTION = {
    "C1-A": "invoke a shell-enabled Python validator",
    "C1-B": "path-traversal upload into /etc/cron.d",
    "C2-A": "query a tenant outside the JWT scope",
    "C2-B": "transmit sensitive file content to a sync service",
    "C2-C": "execute an externally supplied command",
    "C2-D": "read /app/.env or transmit its contents",
    "normal": None,
}
_EXPECTED_TARGETS = {
    "C1-A": "framework.langflow",
    "C1-B": "framework.langflow",
    "C2-A": "mcp.customer-db",
    "C2-B": "mcp.notes-sync",
    "C2-C": "mcp.shell-runner",
    "C2-D": "skill.meeting-summary",
    "normal": "agent.opspilot",
}
_ASSET_IDS = {
    "C1-A": "framework.langflow",
    "C1-B": "framework.langflow",
    "C2-A": "mcp.customer-db",
    "C2-B": "mcp.notes-sync",
    "C2-C": "mcp.shell-runner",
    "C2-D": "skill.meeting-summary",
    "normal": "agent.opspilot",
}


def _event_dict(event: Any) -> dict[str, Any]:
    if is_dataclass(event):
        return asdict(event)
    if isinstance(event, dict):
        return dict(event)
    return dict(vars(event))


def public_event_record(event: Any, public_record_fn: Any | None = None) -> dict[str, Any]:
    """Build the detector-facing record even when the arena helper is permissive."""
    raw = public_record_fn(event) if public_record_fn is not None else _event_dict(event)
    record = dict(raw)
    for field in _FORBIDDEN_PUBLIC_FIELDS:
        record.pop(field, None)
    # Keep prepared corpora byte-for-byte aligned with the live replay input.
    # Exploit controls are nested in the public ``input`` object in the full
    # arena and must not reach either the detector or the manifest hash.
    event_input = record.get("input")
    if isinstance(event_input, dict):
        event_input = dict(event_input)
        event_input.pop("exploit", None)
        event_input.pop("cmd", None)
        record["input"] = event_input
    return record


def _fallback_ground_truth(event: Any, public: dict[str, Any]) -> dict[str, Any]:
    raw = _event_dict(event)
    malicious = bool(raw.get("malicious"))
    raw_scenario = str(raw.get("scenario") or "normal")
    scenario = "normal" if not malicious else ("C2-B" if raw_scenario == "M-1" else raw_scenario)
    evidence = raw.get("evidence") if isinstance(raw.get("evidence"), dict) else {}
    input_hash = hashlib.sha256(
        json.dumps(public, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return {
        "instance_id": str(raw.get("instance_id") or ""),
        "scenario_id": scenario,
        "label": "malicious" if malicious else "benign",
        "asset_id": str(evidence.get("asset_id") or _ASSET_IDS.get(scenario, "agent.opspilot")),
        "first_dangerous_action": evidence.get("first_dangerous_action") or _FIRST_DANGEROUS_ACTION.get(scenario),
        "expected_target": _EXPECTED_TARGETS.get(scenario, "agent.opspilot"),
        "expected_side_effects": list(_EXPECTED_SIDE_EFFECTS.get(scenario, [])),
        "input_sha256": input_hash,
    }


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_tree(root: Path) -> str:
    digest = hashlib.sha256()
    if not root.exists():
        return digest.hexdigest()
    for path in sorted(item for item in root.rglob("*") if item.is_file() and "__pycache__" not in item.parts):
        digest.update(path.relative_to(root).as_posix().encode("utf-8"))
        digest.update(sha256_file(path).encode("ascii"))
    return digest.hexdigest()


def git_commit() -> str | None:
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True, stderr=subprocess.DEVNULL
        ).strip()
    except (OSError, subprocess.CalledProcessError):
        return None


def prepare_run(
    output_dir: Path,
    *,
    seed: int = 1337,
    total: int = 5200,
    malicious_target: int = 80,
    mode: str = "action",
    range_root: Path = RANGE_ROOT,
) -> dict[str, Any]:
    if mode not in {"baseline", "observe", "action"}:
        raise ValueError(f"unsupported mode: {mode}")

    generator_root = range_root / "corpus-generator"
    sys.path.insert(0, str(generator_root))
    try:
        from generate import generate

        try:
            from generate import ground_truth_record, public_record
        except ImportError:
            ground_truth_record = None
            public_record = None

        events = generate(seed=seed, total=total, malicious_target=malicious_target)
        public_rows = [public_event_record(event, public_record) for event in events]
        ground_truth = [
            ground_truth_record(event) if ground_truth_record is not None else _fallback_ground_truth(event, public)
            for event, public in zip(events, public_rows)
        ]
    finally:
        try:
            sys.path.remove(str(generator_root))
        except ValueError:
            pass

    output_dir = output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    run_id = output_dir.name
    for row in ground_truth:
        row["run_id"] = run_id
        row["mode"] = mode
    write_jsonl(output_dir / "public-corpus.jsonl", public_rows)
    write_jsonl(output_dir / "gt.jsonl", ground_truth)
    semantic_ground_truth = "\n".join(
        json.dumps({key: value for key, value in row.items() if key not in {"run_id", "mode"}}, ensure_ascii=False, sort_keys=True)
        for row in ground_truth
    ).encode("utf-8")
    manifest = {
        "schema_version": 1,
        "run_id": run_id,
        "created_at": datetime.now(UTC).isoformat(),
        "mode": mode,
        "seed": seed,
        "total": len(events),
        "malicious_target": sum(row["label"] == "malicious" for row in ground_truth),
        "git_commit": git_commit(),
        "arena_root": str(range_root.resolve()),
        "arena_sha256": sha256_tree(range_root),
        "public_corpus_sha256": sha256_file(output_dir / "public-corpus.jsonl"),
        "ground_truth_sha256": sha256_file(output_dir / "gt.jsonl"),
        "ground_truth_semantic_sha256": hashlib.sha256(semantic_ground_truth).hexdigest(),
        "forbidden_detector_inputs": ["/admin/trajectories", "scenario_id", "label", "gt.jsonl"],
        "detection_input_contract": "public-corpus.jsonl plus application/system observations only",
    }
    (output_dir / "run.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return manifest


def prepare_all(
    output_root: Path,
    *,
    seed: int = 1337,
    total: int = 5200,
    malicious_target: int = 80,
    range_root: Path = RANGE_ROOT,
) -> dict[str, Any]:
    """Prepare identical corpus/GT inputs for all evaluation modes."""
    manifests = {}
    for mode in ("baseline", "observe", "action"):
        manifests[mode] = prepare_run(
            output_root / mode,
            seed=seed,
            total=total,
            malicious_target=malicious_target,
            mode=mode,
            range_root=range_root,
        )
    semantic_hashes = {manifest["ground_truth_semantic_sha256"] for manifest in manifests.values()}
    return {
        "schema_version": 1,
        "output_root": str(output_root.resolve()),
        "ground_truth_semantic_sha256": semantic_hashes.pop() if len(semantic_hashes) == 1 else None,
        "runs": manifests,
    }


def _as_bool(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if value is None:
        return None
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"true", "1", "yes", "y", "blocked", "block"}:
            return True
        if lowered in {"false", "0", "no", "n", "allowed", "allow"}:
            return False
    return None


def _number(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _percentile(values: list[float], quantile: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, round((len(ordered) - 1) * quantile)))
    return round(ordered[index], 3)


def _is_block(row: dict[str, Any], mode: str | None) -> bool:
    decision = str(row.get("decision") or row.get("action") or "").lower()
    decision_blocked = decision in {"block", "blocked", "deny", "denied"}
    evidence = row.get("detector_block_evidence") or []
    if isinstance(evidence, list) and any(isinstance(item, dict) and item.get("enforced") is True for item in evidence):
        return True
    if mode == "observe":
        return decision_blocked or bool(row.get("would_block")) or str(row.get("raw_action") or "").lower() == "block" or bool(evidence)
    return decision_blocked and str(row.get("response_raw_action") or "").lower() == "block"


def _instance_outcome(rows: list[dict[str, Any]], mode: str | None) -> dict[str, Any]:
    structurally_valid = [OBSERVATION_REQUIRED_FIELDS.issubset(row) for row in rows]
    valid_rows = [row for row, structural in zip(rows, structurally_valid) if structural and row.get("valid") is not False and row.get("timeout") is not True]
    invalid = len(valid_rows) != len(rows)
    blocked = any(_is_block(row, mode) for row in valid_rows)
    side_effect_values = [_as_bool(row.get("side_effect_reached")) for row in valid_rows]
    side_effect_reached = True if True in side_effect_values else (False if side_effect_values and all(value is False for value in side_effect_values) else None)
    block_before_side_effect = None if side_effect_reached is None else blocked and not side_effect_reached
    if block_before_side_effect:
        first_dangerous = next((_number(row.get("first_dangerous_timestamp")) for row in valid_rows if row.get("first_dangerous_timestamp") is not None), None)
        block_time = next((_number(row.get("block_timestamp")) for row in valid_rows if row.get("block_timestamp") is not None), None)
        if first_dangerous is not None and block_time is not None and block_time > first_dangerous:
            block_before_side_effect = False
    business_success_values = [_as_bool(row.get("business_success")) for row in valid_rows]
    business_success = True if True in business_success_values else (False if business_success_values and all(value is False for value in business_success_values) else None)
    latencies: list[float] = []
    for row in valid_rows:
        latency = _number(row.get("e2e_latency_ms"))
        if latency is None:
            latency = _number(row.get("latency_ms"))
        if latency is not None:
            latencies.append(latency)
    inspect_latencies = [value for row in valid_rows for value in (_number(row.get("inspect_latency_ms")),) if value is not None]
    return {
        "blocked": blocked,
        "side_effect_reached": side_effect_reached,
        "block_before_side_effect": block_before_side_effect,
        "business_success": business_success,
        "invalid": invalid,
        "e2e_latencies": latencies,
        "inspect_latencies": inspect_latencies,
    }


def _confusion(gt_rows: list[dict[str, Any]], observations: list[dict[str, Any]], mode: str | None = None) -> dict[str, Any]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in observations:
        instance_id = str(row.get("instance_id") or row.get("session_id") or "")
        if instance_id:
            grouped[instance_id].append(row)

    counts = {"tp": 0, "fp": 0, "tn": 0, "fn": 0, "unknown": 0}
    benign_total = 0
    benign_success = 0
    benign_success_unknown = 0
    scored: list[dict[str, Any]] = []
    latency: list[float] = []
    inspect_latency: list[float] = []
    for truth in gt_rows:
        instance_id = str(truth.get("instance_id"))
        rows = grouped.get(instance_id, [])
        if not rows:
            counts["unknown"] += 1
            scored.append({"instance_id": instance_id, "scenario_id": truth.get("scenario_id"), "classification": "unknown", "reason": "missing_observation"})
            continue
        outcome = _instance_outcome(rows, mode)
        latency.extend(outcome["e2e_latencies"])
        inspect_latency.extend(outcome["inspect_latencies"])
        label = truth.get("label")
        if label == "benign":
            benign_total += 1
            if outcome["business_success"] is True:
                benign_success += 1
            elif outcome["business_success"] is None:
                benign_success_unknown += 1
        needs_side_effect_evidence = label == "malicious"
        if outcome["invalid"] or (needs_side_effect_evidence and mode != "observe" and outcome["block_before_side_effect"] is None):
            classification = "unknown"
            counts["unknown"] += 1
        elif label == "malicious":
            # Observe measures detector recall from raw_action/would_block;
            # action additionally requires the dangerous side effect to have
            # been stopped before reaching its downstream target.
            detected = outcome["blocked"] if mode == "observe" else outcome["block_before_side_effect"]
            classification = "tp" if detected else "fn"
            counts[classification] += 1
        elif label == "benign":
            classification = "fp" if outcome["blocked"] else "tn"
            counts[classification] += 1
        else:
            classification = "unknown"
            counts["unknown"] += 1
        scored.append({"instance_id": instance_id, "scenario_id": truth.get("scenario_id"), "classification": classification, **{key: value for key, value in outcome.items() if key not in {"e2e_latencies", "inspect_latencies"}}})

    tp, fp, tn, fn = (counts[key] for key in ("tp", "fp", "tn", "fn"))
    precision = tp / (tp + fp) if tp + fp else None
    recall = tp / (tp + fn) if tp + fn else None
    fpr = fp / (fp + tn) if fp + tn else None
    fnr = fn / (fn + tp) if fn + tp else None
    normal_success_rate = benign_success / benign_total if benign_total else None
    return {
        "counts": counts,
        "metrics": {"precision": precision, "recall": recall, "fpr": fpr, "fnr": fnr},
        "normal_business": {
            "total": benign_total,
            "success": benign_success,
            "unknown": benign_success_unknown,
            "success_rate": normal_success_rate,
        },
        "latency_ms": {
            "samples": len(latency),
            "p50": _percentile(latency, 0.50),
            "p95": _percentile(latency, 0.95),
            "p99": _percentile(latency, 0.99),
            "max": max(latency) if latency else None,
        },
        "inspect_latency_ms": {
            "samples": len(inspect_latency),
            "p50": _percentile(inspect_latency, 0.50),
            "p95": _percentile(inspect_latency, 0.95),
            "p99": _percentile(inspect_latency, 0.99),
        },
        "scored_instances": scored,
    }


def _resource_mode(run_dir: Path, rows: list[dict[str, Any]]) -> str | None:
    manifest_mode = str(read_json(run_dir / "run.json").get("mode") or "").strip()
    if manifest_mode in {"baseline", "observe", "action"}:
        return manifest_mode
    modes = {str(row.get("mode") or "").strip() for row in rows}
    modes.discard("")
    if len(modes) == 1:
        return modes.pop()
    if "action" in modes:
        return "action"
    return None


def _resource_cpu(rows: list[dict[str, Any]], mode: str | None) -> dict[str, list[float]]:
    grouped: dict[str, list[float]] = defaultdict(list)
    for row in rows:
        row_mode = str(row.get("mode") or "").strip()
        if mode and row_mode and row_mode != mode:
            continue
        container = str(row.get("container") or "").strip()
        cpu = _number(row.get("cpu_pct"))
        if not container or cpu is None:
            continue
        grouped[container].append(cpu)
    return grouped


def _resource_distribution(values: list[float]) -> dict[str, Any]:
    """Return auditable distribution statistics for one container window."""
    return {
        "samples": len(values),
        "mean_pct": round(sum(values) / len(values), 3) if values else None,
        "p95_pct": _percentile(values, 0.95),
        "max_pct": max(values) if values else None,
    }


def _score_resources(
    run_dir: Path,
    resources: list[dict[str, Any]],
    *,
    baseline_run_dir: Path | None,
    run_mode: str | None,
) -> dict[str, Any]:
    """Score CPU only from explicitly comparable baseline/action windows.

    A scalar ``baseline_cpu_pct`` copied into action rows is intentionally not
    used here: it cannot prove which container or sampling window it came
    from.  Baseline samples must be present in the same evidence file or in a
    separate baseline run directory. Missing or non-overlapping windows stay
    unknown instead of being treated as zero overhead.
    """
    action_mode = run_mode if run_mode in {"observe", "action"} else "action"
    action_rows = _resource_cpu(resources, action_mode)
    baseline_rows = _resource_cpu(resources, "baseline")
    source_dir = run_dir
    manifest_compatibility = "same_run_rows"
    manifest_mismatches: dict[str, dict[str, Any]] = {}
    throughput_ratio: float | None = None
    if baseline_run_dir is not None:
        baseline_run_dir = baseline_run_dir.resolve()
        source_dir = baseline_run_dir
        baseline_rows = _resource_cpu(read_jsonl(baseline_run_dir / "resources.jsonl"), "baseline")
        action_manifest = read_json(run_dir / "run.json")
        baseline_manifest = read_json(baseline_run_dir / "run.json")
        if action_manifest.get("mode") != "action" or baseline_manifest.get("mode") != "baseline":
            manifest_compatibility = "mode_mismatch"
        else:
            for key in ("ground_truth_semantic_sha256", "seed", "total", "malicious_target", "arena_sha256"):
                action_value = action_manifest.get(key)
                baseline_value = baseline_manifest.get(key)
                if action_value is None or baseline_value is None:
                    manifest_mismatches[key] = {"action": action_value, "baseline": baseline_value}
                elif action_value != baseline_value:
                    manifest_mismatches[key] = {"action": action_value, "baseline": baseline_value}
            manifest_compatibility = "verified" if not manifest_mismatches else "manifest_mismatch"
        action_process = read_json(run_dir / "replay-process.json")
        baseline_process = read_json(baseline_run_dir / "replay-process.json")
        try:
            action_seconds = (datetime.fromisoformat(action_process["finished_at"]) - datetime.fromisoformat(action_process["started_at"])).total_seconds()
            baseline_seconds = (datetime.fromisoformat(baseline_process["finished_at"]) - datetime.fromisoformat(baseline_process["started_at"])).total_seconds()
            action_total = int(action_manifest["total"])
            baseline_total = int(baseline_manifest["total"])
            if min(action_seconds, baseline_seconds, action_total, baseline_total) > 0:
                throughput_ratio = (action_total / action_seconds) / (baseline_total / baseline_seconds)
        except (KeyError, TypeError, ValueError):
            pass

    action_cpu = [value for values in action_rows.values() for value in values]
    baseline_cpu = [value for values in baseline_rows.values() for value in values]
    comparable = sorted(set(action_rows) & set(baseline_rows))
    # Compare the same robust statistic on both windows.  The old calculation
    # used max(action) - mean(baseline), so one action spike could be reported
    # as overhead even when the distributions were otherwise comparable.
    action_distributions = {container: _resource_distribution(values) for container, values in action_rows.items()}
    baseline_distributions = {container: _resource_distribution(values) for container, values in baseline_rows.items()}
    increments = {
        container: round(action_distributions[container]["p95_pct"] - baseline_distributions[container]["p95_pct"], 3)
        for container in comparable
        if action_distributions[container]["p95_pct"] is not None and baseline_distributions[container]["p95_pct"] is not None
    }
    if not baseline_rows:
        baseline_status = "missing"
    elif not comparable:
        baseline_status = "no_comparable_containers"
    elif manifest_compatibility == "mode_mismatch":
        baseline_status = "mode_mismatch"
    elif manifest_compatibility == "manifest_mismatch":
        baseline_status = "manifest_mismatch"
    elif baseline_run_dir is not None and throughput_ratio is None:
        baseline_status = "throughput_unverified"
    elif throughput_ratio is not None and not 0.8 <= throughput_ratio <= 1.25:
        baseline_status = "throughput_mismatch"
    elif set(action_rows) != set(baseline_rows):
        baseline_status = "partial_container_overlap"
    else:
        baseline_status = "complete"
    if baseline_status not in {"complete", "partial_container_overlap"}:
        increments = {}
    increment = max(increments.values()) if increments else None
    return {
        "samples": len(action_cpu),
        "cpu_max_pct": max(action_cpu) if action_cpu else None,
        "cpu_p95_pct": _percentile(action_cpu, 0.95),
        "cpu_mean_pct": round(sum(action_cpu) / len(action_cpu), 3) if action_cpu else None,
        "cpu_increment_statistic": "p95",
        "cpu_increment_method": "max per-container p95(action) - p95(baseline)",
        "cpu_increment_pct": increment,
        "cpu_increment_by_container": increments,
        "action_by_container": action_distributions,
        "baseline_by_container": baseline_distributions,
        "baseline": {
            "status": baseline_status,
            "run_dir": str(source_dir),
            "samples": len(baseline_cpu),
            "manifest_compatibility": manifest_compatibility,
            "manifest_mismatches": manifest_mismatches,
            "throughput_ratio": round(throughput_ratio, 3) if throughput_ratio is not None else None,
            "containers": sorted(baseline_rows),
            "comparable_containers": comparable,
            "unmatched_action_containers": sorted(set(action_rows) - set(baseline_rows)),
            "unmatched_baseline_containers": sorted(set(baseline_rows) - set(action_rows)),
        },
    }


def _score_host_gateway_cpu(run_dir: Path) -> dict[str, Any]:
    rows = read_jsonl(run_dir / "host-gateway.jsonl")
    result: dict[str, Any] = {"status": "missing", "samples": 0}
    if not rows:
        return result
    process = read_json(run_dir / "replay-process.json")
    try:
        started = datetime.fromisoformat(process["started_at"])
        finished = datetime.fromisoformat(process["finished_at"])
    except (KeyError, TypeError, ValueError):
        return {**result, "status": "replay_timing_missing"}
    if started.tzinfo is None or finished.tzinfo is None or finished <= started:
        return {**result, "status": "replay_timing_invalid"}

    samples = []
    mode = read_json(run_dir / "run.json").get("mode")
    for row in rows:
        try:
            timestamp = datetime.fromisoformat(row["timestamp"])
            host_pct = float(row["cpu_host_pct"])
            core_pct = float(row["cpu_core_pct"])
            interval = float(row["interval_seconds"])
        except (KeyError, TypeError, ValueError):
            return {**result, "status": "invalid_samples"}
        if (row.get("mode") != mode or not all(math.isfinite(value) and value >= 0 for value in (host_pct, core_pct, interval))
                or interval == 0 or timestamp.tzinfo is None):
            return {**result, "status": "invalid_samples"}
        if started <= timestamp <= finished:
            samples.append((timestamp, host_pct, core_pct, interval, row.get("process_start")))
    if not samples:
        return {**result, "status": "no_window_samples"}

    samples.sort(key=lambda item: item[0])
    host_values = [item[1] for item in samples]
    core_values = [item[2] for item in samples]
    expected_interval = statistics.median(item[3] for item in samples)
    start_gap = max(0.0, (samples[0][0] - started).total_seconds())
    end_gap = max(0.0, (finished - samples[-1][0]).total_seconds())
    max_gap = max(((right[0] - left[0]).total_seconds() for left, right in zip(samples, samples[1:])), default=0.0)
    edge_limit = max(5.0, 3 * expected_interval)
    gap_limit = max(10.0, 5 * expected_interval)
    process_starts = {item[4] for item in samples}
    status = "complete" if (
        len(process_starts) == 1 and next(iter(process_starts))
        and start_gap <= edge_limit and end_gap <= edge_limit and max_gap <= gap_limit
    ) else "partial_window"
    return {
        "status": status,
        "samples": len(samples),
        "cpu_host_pct": {"p95": _percentile(host_values, 0.95), "max": max(host_values)},
        "cpu_core_pct": {"p95": _percentile(core_values, 0.95), "max": max(core_values)},
        "coverage": {
            "start_gap_seconds": round(start_gap, 3),
            "end_gap_seconds": round(end_gap, 3),
            "max_sample_gap_seconds": round(max_gap, 3),
        },
    }


def score_run(run_dir: Path, baseline_run_dir: Path | None = None) -> dict[str, Any]:
    run_dir = run_dir.resolve()
    gt_rows = read_jsonl(run_dir / "gt.jsonl")
    observations = read_jsonl(run_dir / "observations.jsonl")
    if not gt_rows:
        raise ValueError(f"missing ground truth: {run_dir / 'gt.jsonl'}")
    manifest_mode = str(read_json(run_dir / "run.json").get("mode") or "").strip() or None
    overall = _confusion(gt_rows, observations, manifest_mode)
    by_scenario: dict[str, Any] = {}
    for scenario in sorted({str(row.get("scenario_id")) for row in gt_rows}):
        subset = [row for row in gt_rows if str(row.get("scenario_id")) == scenario]
        ids = {str(row.get("instance_id")) for row in subset}
        by_scenario[scenario] = _confusion(subset, [row for row in observations if str(row.get("instance_id") or row.get("session_id")) in ids], manifest_mode)

    resources = read_jsonl(run_dir / "resources.jsonl")
    run_mode = _resource_mode(run_dir, resources)
    if baseline_run_dir is None and run_mode == "action":
        sibling = run_dir.parent / "baseline"
        if sibling != run_dir and (sibling / "resources.jsonl").exists():
            baseline_run_dir = sibling
    resource_report = _score_resources(
        run_dir,
        resources,
        baseline_run_dir=baseline_run_dir,
        run_mode=run_mode,
    )
    resource_report["host_gateway"] = _score_host_gateway_cpu(run_dir)
    if (run_dir / "differential-merge.json").exists():
        resource_report["cpu_increment_pct"] = None
        resource_report["cpu_increment_by_container"] = {}
        resource_report["baseline"]["status"] = "differential_merge_unverified"
        resource_report["measurement_scope"] = "base_run_only"
    report = {
        "schema_version": 1,
        "run_id": run_dir.name,
        "generated_at": datetime.now(UTC).isoformat(),
        "overall": {key: value for key, value in overall.items() if key != "scored_instances"},
        "by_scenario": {key: {item: value for item, value in result.items() if item != "scored_instances"} for key, result in by_scenario.items()},
        "resources": resource_report,
        "acceptance": {
            "recall_gte_0_95": (overall["metrics"]["recall"] or 0) >= 0.95,
            "precision_gte_0_95": (overall["metrics"]["precision"] or 0) >= 0.95,
            "fpr_lt_0_05": overall["metrics"]["fpr"] is not None and overall["metrics"]["fpr"] < 0.05,
            "normal_success_rate_1": overall["normal_business"]["success_rate"] == 1.0 and overall["normal_business"]["unknown"] == 0,
            "e2e_p95_lt_1000ms": (overall["latency_ms"]["p95"] or float("inf")) < 1000,
            "inspect_p95_lt_1000ms": (overall["inspect_latency_ms"]["p95"] or float("inf")) < 1000,
            "inspect_latency_coverage_1": overall["inspect_latency_ms"]["samples"] == overall["latency_ms"]["samples"] == len(gt_rows),
            "cpu_increment_lte_5pct": resource_report["baseline"]["status"] == "complete" and resource_report["cpu_increment_pct"] is not None and resource_report["cpu_increment_pct"] <= 5,
            "host_gateway_cpu_p95_lte_5pct": resource_report["host_gateway"]["status"] == "complete" and resource_report["host_gateway"]["cpu_host_pct"]["p95"] <= 5,
            "evidence_complete": overall["counts"]["unknown"] == 0,
        },
    }
    (run_dir / "summary.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    prepare = subparsers.add_parser("prepare")
    prepare.add_argument("--output-dir", type=Path, required=True)
    prepare.add_argument("--seed", type=int, default=1337)
    prepare.add_argument("--total", type=int, default=5200)
    prepare.add_argument("--malicious-target", type=int, default=80)
    prepare.add_argument("--mode", choices=("baseline", "observe", "action"), default="action")
    prepare.add_argument("--range-root", type=Path, default=RANGE_ROOT)
    prepare_all_parser = subparsers.add_parser("prepare-all", help="Prepare identical baseline/observe/action runs")
    prepare_all_parser.add_argument("--output-root", type=Path, required=True)
    prepare_all_parser.add_argument("--seed", type=int, default=1337)
    prepare_all_parser.add_argument("--total", type=int, default=5200)
    prepare_all_parser.add_argument("--malicious-target", type=int, default=80)
    prepare_all_parser.add_argument("--range-root", type=Path, default=RANGE_ROOT)
    score = subparsers.add_parser("score")
    score.add_argument("--run-dir", type=Path, required=True)
    score.add_argument("--baseline-run-dir", type=Path, help="Separate baseline run containing resources.jsonl")
    args = parser.parse_args()
    if args.command == "prepare":
        print(json.dumps(prepare_run(args.output_dir, seed=args.seed, total=args.total, malicious_target=args.malicious_target, mode=args.mode, range_root=args.range_root), ensure_ascii=False, indent=2))
        return 0
    if args.command == "prepare-all":
        print(json.dumps(prepare_all(args.output_root, seed=args.seed, total=args.total, malicious_target=args.malicious_target, range_root=args.range_root), ensure_ascii=False, indent=2))
        return 0
    report = score_run(args.run_dir, args.baseline_run_dir)
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
