"""Run and summarize reproducible baseline/observe/action AgentRange benchmarks."""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import subprocess
import sys
from datetime import UTC, datetime


ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scenario-runner"))
sys.path.insert(0, str(ROOT / "attack"))
sys.path.insert(0, str(ROOT / "corpus-generator"))

from runner import percentile, replay_generated


def docker_stats() -> dict:
    try:
        process = subprocess.run(
            ["docker", "stats", "--no-stream", "--format", "{{json .}}"],
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return {"available": False, "error": f"{type(exc).__name__}: {exc}"}
    rows = []
    for line in process.stdout.splitlines():
        try:
            rows.append(json.loads(line))
        except ValueError:
            continue
    return {"available": process.returncode == 0, "rows": rows, "stderr": process.stderr.strip()}


def load_inspect_latencies(report_dir: pathlib.Path) -> list[float]:
    values = []
    for path in report_dir.glob("*-events.jsonl"):
        for line in path.read_text(encoding="utf-8").splitlines():
            try:
                value = (json.loads(line).get("decision") or {}).get("latency_ms")
                if value is not None:
                    values.append(float(value))
            except (ValueError, TypeError):
                continue
    return values


def run_mode(mode: str, output: pathlib.Path, seed: int, total: int, malicious_target: int) -> dict:
    before = docker_stats()
    report = replay_generated(seed=seed, total=total, malicious_target=malicious_target, mode=mode)
    after = docker_stats()
    inspect = load_inspect_latencies(ROOT / "integration" / "reports")
    report.update(
        {
            "mode": mode,
            "generated_at": datetime.now(UTC).isoformat(),
            "environment": {"platform": sys.platform, "python": sys.version.split()[0], "defenseclaw_api_configured": bool(os.getenv("DEFENSECLAW_API_BASE"))},
            "resources": {"before": before, "after": after},
            "inspect_latency_ms": {
                "samples": len(inspect),
                "p50": round(percentile(inspect, 0.50), 3),
                "p95": round(percentile(inspect, 0.95), 3),
                "p99": round(percentile(inspect, 0.99), 3),
            },
        }
    )
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    return report


def parse_cpu(snapshot: dict) -> float | None:
    rows = snapshot.get("rows") or []
    values = []
    for row in rows:
        raw = str(row.get("CPUPerc") or row.get("CPU %") or "").strip().rstrip("%")
        try:
            values.append(float(raw))
        except ValueError:
            pass
    return sum(values) if values else None


def summarize(result_dir: pathlib.Path, output: pathlib.Path) -> dict:
    reports = {}
    for mode in ("baseline", "observe", "action"):
        path = result_dir / f"{mode}.json"
        if path.exists():
            reports[mode] = json.loads(path.read_text(encoding="utf-8"))
    summary = {"modes": {}, "acceptance": {}, "missing_modes": sorted(set(("baseline", "observe", "action")) - set(reports))}
    baseline_cpu = parse_cpu((reports.get("baseline", {}).get("resources") or {}).get("after") or {})
    for mode, report in reports.items():
        cpu = parse_cpu((report.get("resources") or {}).get("after") or {})
        summary["modes"][mode] = {
            "counts": report.get("counts"),
            "metrics": report.get("metrics"),
            "inspect_latency_ms": report.get("inspect_latency_ms"),
            "cpu_total_pct": cpu,
            "cpu_increment_pct": round(cpu - baseline_cpu, 3) if cpu is not None and baseline_cpu is not None else None,
        }
    action = summary["modes"].get("action", {})
    metrics = action.get("metrics") or {}
    inspect = action.get("inspect_latency_ms") or {}
    summary["acceptance"] = {
        "recall_gte_0_95": metrics.get("recall", 0) >= 0.95,
        "fpr_lt_0_05": metrics.get("fpr", 1) < 0.05,
        "inspect_p95_lt_1000ms": inspect.get("p95", 1000) < 1000,
        "normal_success_rate_1": metrics.get("normal_success_rate", 0) == 1.0,
        "cpu_increment_lte_5pct": action.get("cpu_increment_pct") is not None and action["cpu_increment_pct"] <= 5,
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    run = sub.add_parser("run")
    run.add_argument("--mode", choices=("baseline", "observe", "action"), required=True)
    run.add_argument("--seed", type=int, default=1337)
    run.add_argument("--total", type=int, default=5200)
    run.add_argument("--malicious-target", type=int, default=80)
    run.add_argument("--output", type=pathlib.Path)
    aggregate = sub.add_parser("summarize")
    aggregate.add_argument("--result-dir", type=pathlib.Path, default=ROOT / "bench" / "results")
    aggregate.add_argument("--output", type=pathlib.Path, default=ROOT / "bench" / "results" / "summary.json")
    args = parser.parse_args()
    if args.command == "run":
        output = args.output or ROOT / "bench" / "results" / f"{args.mode}.json"
        report = run_mode(args.mode, output, args.seed, args.total, args.malicious_target)
        print(json.dumps({"output": str(output), "mode": args.mode, "counts": report["counts"], "metrics": report["metrics"]}, ensure_ascii=False, indent=2))
        return 0
    report = summarize(args.result_dir, args.output)
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if not report["missing_modes"] and all(report["acceptance"].values()) else 2


if __name__ == "__main__":
    raise SystemExit(main())
