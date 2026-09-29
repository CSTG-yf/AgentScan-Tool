"""Summarize AgentRange DefenseClaw benchmark and runtime evidence."""

from __future__ import annotations

import argparse
import json
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

try:
    from agentrange_benchmark import prepare_all, prepare_run, score_run
except ImportError:  # pragma: no cover - package import when called as bench module
    from bench.agentrange_benchmark import prepare_all, prepare_run, score_run

ROOT = Path(__file__).resolve().parents[1]
REPORTS = ROOT / "integration" / "reports"
RESULTS = ROOT / "bench" / "results"
MODES = ("baseline", "observe", "action")


def read_json(path: Path, default: Any = None) -> Any:
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return default


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    rows: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line.strip():
            continue
        try:
            parsed = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(parsed, dict):
            rows.append(parsed)
    return rows


def percentile(values: list[float], quantile: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, round((len(ordered) - 1) * quantile)))
    return ordered[index]


def summarize_events(events: list[dict[str, Any]]) -> dict[str, Any]:
    decisions = Counter(str(event.get("decision") or "unknown") for event in events)
    severities = Counter(str(event.get("severity") or "INFO") for event in events)
    stages = Counter(str(event.get("stage") or "unknown") for event in events)
    tools = Counter(str(event.get("tool_name") or event.get("mcp_server") or "") for event in events)
    tools.pop("", None)
    sessions = {str(event.get("session_id") or event.get("trace_id") or event.get("event_id")) for event in events}
    latencies = [float(event["latency_ms"]) for event in events if isinstance(event.get("latency_ms"), (int, float))]
    return {
        "source": str(REPORTS / "runtime-events.jsonl"),
        "event_count": len(events),
        "session_count": len(sessions),
        "blocked_event_count": decisions.get("block", 0),
        "inspect_unavailable_count": decisions.get("inspect_unavailable", 0),
        "decisions": dict(decisions),
        "severities": dict(severities),
        "stages": dict(stages),
        "top_tools": dict(tools.most_common(10)),
        "latency_ms": {
            "count": len(latencies),
            "mean": round(sum(latencies) / len(latencies), 3) if latencies else 0.0,
            "p50": round(percentile(latencies, 0.50), 3),
            "p95": round(percentile(latencies, 0.95), 3),
            "p99": round(percentile(latencies, 0.99), 3),
            "max": round(max(latencies), 3) if latencies else 0.0,
        },
        "acceptance": {
            "runtime_events_present": len(events) > 0,
            "agentrange_connector_seen": any(str(event.get("connector")) == "agentrange" for event in events),
        },
    }


def parse_cpu(snapshot: dict[str, Any]) -> float | None:
    rows = snapshot.get("rows") or []
    values: list[float] = []
    for row in rows:
        raw = str(row.get("CPUPerc") or row.get("CPU %") or "").strip().rstrip("%")
        try:
            values.append(float(raw))
        except ValueError:
            pass
    return sum(values) if values else None


def _number(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def normalize_mode_report(report: dict[str, Any]) -> dict[str, Any]:
    overall = report.get("overall") or {}
    counts = report.get("counts") or overall.get("counts") or {}
    metrics = dict(report.get("metrics") or overall.get("metrics") or {})
    normal_business = overall.get("normal_business") or {}
    if "normal_success_rate" not in metrics and "success_rate" in normal_business:
        metrics["normal_success_rate"] = normal_business.get("success_rate")
    latency = report.get("latency_ms") or overall.get("latency_ms") or metrics.get("latency_ms") or report.get("inspect_latency_ms") or {}
    return {
        "counts": counts,
        "metrics": metrics,
        "inspect_latency_ms": report.get("inspect_latency_ms") or overall.get("inspect_latency_ms") or latency,
        "latency_ms": latency,
        "resources": report.get("resources") or {},
        "config": report.get("config") or {},
    }


def summarize_modes(result_dir: Path) -> dict[str, Any]:
    reports: dict[str, dict[str, Any]] = {}
    for mode in MODES:
        payload = read_json(result_dir / f"{mode}.json")
        if isinstance(payload, dict):
            reports[mode] = normalize_mode_report(payload)

    action_resources = (reports.get("action") or {}).get("resources") or {}
    scored_cpu = "cpu_increment_statistic" in action_resources
    if scored_cpu:
        cpu_increment = _number(action_resources.get("cpu_increment_pct"))
        cpu_status = str((action_resources.get("baseline") or {}).get("status") or "unknown")
        cpu_statistic = str(action_resources.get("cpu_increment_statistic"))
        cpu_method = action_resources.get("cpu_increment_method")
        cpu_by_container = action_resources.get("cpu_increment_by_container") or {}
    else:
        # ``resources.after`` is a single snapshot and cannot establish a
        # comparable baseline/action window. Keep it visible as an explicit
        # legacy state, but never derive an acceptance metric from it.
        cpu_increment = None
        cpu_status = "legacy_snapshot_unverified"
        cpu_statistic = None
        cpu_method = None
        cpu_by_container = {}
    modes: dict[str, Any] = {}
    for mode, report in reports.items():
        resources = report.get("resources") or {}
        modes[mode] = {
            "counts": report.get("counts"),
            "metrics": report.get("metrics"),
            "inspect_latency_ms": report.get("inspect_latency_ms"),
            "cpu_total_pct": _number(resources.get("cpu_p95_pct")) if scored_cpu else None,
            "cpu_increment_pct": cpu_increment if mode == "action" else None,
            "cpu_increment_statistic": cpu_statistic if mode == "action" else None,
            "cpu_comparison_status": cpu_status if mode == "action" else None,
            "cpu_increment_method": cpu_method if mode == "action" else None,
            "cpu_increment_by_container": cpu_by_container if mode == "action" else {},
        }

    action = modes.get("action", {})
    metrics = action.get("metrics") or {}
    inspect = action.get("inspect_latency_ms") or {}
    inspect_p95 = _number(inspect.get("p95"))
    return {
        "modes": modes,
        "missing_modes": sorted(set(MODES) - set(reports)),
        "acceptance": {
            "recall_gte_0_95": metrics.get("recall", 0) >= 0.95,
            "fpr_lt_0_05": metrics.get("fpr", 1) < 0.05,
            "inspect_p95_lt_1000ms": inspect_p95 is not None and inspect_p95 < 1000,
            "normal_success_rate_1": metrics.get("normal_success_rate", 0) == 1.0,
            "cpu_increment_lte_5pct": cpu_status == "complete" and cpu_increment is not None and cpu_increment <= 5,
        },
    }


def build_summary(result_dir: Path = RESULTS) -> dict[str, Any]:
    events = load_jsonl(REPORTS / "runtime-events.jsonl")
    mode_summary = summarize_modes(result_dir)
    return {
        "schema_version": 1,
        "generated_at": datetime.now(UTC).isoformat(),
        "runtime": summarize_events(events),
        **mode_summary,
    }


def summarize(result_dir: Path = RESULTS, output: Path = RESULTS / "summary.json") -> dict[str, Any]:
    # Backward compatibility with the previous summarize(output) helper.
    if result_dir.suffix == ".json" and output == RESULTS / "summary.json":
        output = result_dir
        result_dir = RESULTS
    report = build_summary(result_dir)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({"output": str(output), "events": report["runtime"]["event_count"]}, ensure_ascii=False))
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command")
    summarize_parser = subparsers.add_parser("summarize", help="Write bench/results/summary.json")
    summarize_parser.add_argument("--result-dir", type=Path, default=RESULTS)
    summarize_parser.add_argument("--output", type=Path, default=RESULTS / "summary.json")
    prepare_parser = subparsers.add_parser("prepare", help="Create an isolated corpus and private ground truth")
    prepare_parser.add_argument("--output-dir", type=Path, required=True)
    prepare_parser.add_argument("--seed", type=int, default=1337)
    prepare_parser.add_argument("--total", type=int, default=5200)
    prepare_parser.add_argument("--malicious-target", type=int, default=80)
    prepare_parser.add_argument("--mode", choices=MODES, default="action")
    prepare_parser.add_argument("--range-root", type=Path, default=ROOT / "task" / "AgentRange-player-full")
    score_parser = subparsers.add_parser("score", help="Score per-instance observations after side-effect probes")
    score_parser.add_argument("--run-dir", type=Path, required=True)
    score_parser.add_argument("--baseline-run-dir", type=Path, help="Separate baseline run containing resources.jsonl")
    prepare_all_parser = subparsers.add_parser("prepare-all", help="Prepare identical baseline/observe/action runs")
    prepare_all_parser.add_argument("--output-root", type=Path, required=True)
    prepare_all_parser.add_argument("--seed", type=int, default=1337)
    prepare_all_parser.add_argument("--total", type=int, default=5200)
    prepare_all_parser.add_argument("--malicious-target", type=int, default=80)
    prepare_all_parser.add_argument("--range-root", type=Path, default=ROOT / "task" / "AgentRange-player-full")
    args = parser.parse_args()
    if args.command == "prepare":
        report = prepare_run(
            args.output_dir,
            seed=args.seed,
            total=args.total,
            malicious_target=args.malicious_target,
            mode=args.mode,
            range_root=args.range_root,
        )
        print(json.dumps(report, ensure_ascii=False, indent=2))
        return 0
    if args.command == "score":
        print(json.dumps(score_run(args.run_dir, args.baseline_run_dir), ensure_ascii=False, indent=2))
        return 0
    if args.command == "prepare-all":
        print(json.dumps(prepare_all(args.output_root, seed=args.seed, total=args.total, malicious_target=args.malicious_target, range_root=args.range_root), ensure_ascii=False, indent=2))
        return 0
    if args.command in {None, "summarize"}:
        summarize(
            args.result_dir if hasattr(args, "result_dir") else RESULTS,
            args.output if hasattr(args, "output") else RESULTS / "summary.json",
        )
        return 0
    parser.error(f"unknown command: {args.command}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
