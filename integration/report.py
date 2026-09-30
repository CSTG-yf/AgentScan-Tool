"""Aggregate AgentRange non-invasive DefenseClaw validation evidence."""

from __future__ import annotations

import argparse
import json
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

try:
    from requirements_contract import evaluate as evaluate_requirements
except ImportError:  # pragma: no cover - used when imported as integration.report
    from integration.requirements_contract import evaluate as evaluate_requirements

ROOT = Path(__file__).resolve().parents[1]
REPORTS = ROOT / "integration" / "reports"
RESULTS = ROOT / "bench" / "results"


def read_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return default


def read_required_json(path: Path) -> dict[str, Any]:
    parsed = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(parsed, dict):
        raise ValueError(f"expected a JSON object: {path}")
    return parsed


def read_jsonl(path: Path, *, strict: bool = False) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    events: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line.strip():
            continue
        try:
            parsed = json.loads(line)
        except json.JSONDecodeError:
            if strict:
                raise
            continue
        if isinstance(parsed, dict):
            events.append(parsed)
        elif strict:
            raise ValueError(f"expected a JSON object in {path}")
    return events


def representative_chains(chains: list[dict[str, Any]]) -> list[dict[str, Any]]:
    selected = []
    seen_types = set()
    for chain in chains:
        if not chain.get("blocked") or chain.get("sequence_type") in seen_types:
            continue
        selected.append(chain)
        seen_types.add(chain.get("sequence_type"))
        if len(selected) == 6:
            break
    selected.extend(chain for chain in chains if not chain.get("blocked") and len(selected) < len(seen_types) + 2)
    return selected


def build_report(root: Path = ROOT, benchmark_run_dir: Path | None = None) -> dict[str, Any]:
    reports = root / "integration" / "reports"
    results = root / "bench" / "results"
    run_dir = benchmark_run_dir.resolve() if benchmark_run_dir else None
    action_dir = (run_dir / "action" if (run_dir / "action").is_dir() else run_dir) if run_dir else None
    if action_dir:
        required = [action_dir / name for name in ("run.json", "summary.json", "runtime-events.jsonl", "attack-chains.json")]
        missing = [str(path) for path in required if not path.is_file()]
        if missing:
            raise FileNotFoundError("scoped report requires: " + ", ".join(missing))
    events = read_jsonl((action_dir or reports) / "runtime-events.jsonl", strict=bool(action_dir))
    chains_doc = (read_required_json(action_dir / "attack-chains.json") if action_dir
                  else read_json(reports / "attack-chains.json", {"chains": []}))
    if action_dir and chains_doc.get("event_count") != len(events):
        raise ValueError("scoped chain and event counts differ")
    static = read_json(reports / "static-scan.json", {})
    static_evaluation = read_json(reports / "static-eval.json", {})
    rules = read_json(reports / "rule-contract.json", {})
    benchmark = (read_required_json(action_dir / "summary.json") if action_dir
                 else read_json(results / "summary.json", {}))
    if action_dir:
        action_manifest = read_required_json(action_dir / "run.json")
        baseline_dir = action_dir.parent / "baseline"
        baseline_manifest = read_json(baseline_dir / "run.json", {})
        baseline_resource = ((benchmark.get("resources") or {}).get("baseline") or {})
        benchmark_provenance = {
            "comparable_mode_set": (baseline_resource.get("status") == "complete"
                                    and baseline_resource.get("manifest_compatibility") == "verified"
                                    and bool(baseline_manifest)),
            "action_run": action_dir.relative_to(root).as_posix(),
            "baseline_run": baseline_dir.relative_to(root).as_posix() if baseline_manifest else None,
            "git_commit": action_manifest.get("git_commit"),
            "arena_sha256": action_manifest.get("arena_sha256"),
            "notes": ["Runtime events and chains are scoped to this action replay and its observed instance IDs."],
        }
    else:
        benchmark_provenance = read_json(results / "source-manifest.json", {})
    chains = chains_doc.get("chains", [])
    decisions = Counter(str(event.get("decision") or "unknown") for event in events)
    severities = Counter(str(event.get("severity") or "INFO") for event in events)
    sessions = {
        event.get("session_id") or event.get("trace_id") or event.get("event_id")
        for event in events
    }
    traceability = evaluate_requirements(root)
    traceability["scope"] = "repository_path_existence_only"
    static_metrics = static.get("metrics") or {}
    runtime_summary = {
        "event_count": len(events),
        "session_count": len(sessions),
        "attack_chain_count": len(chains),
        "blocked_chain_count": sum(bool(chain.get("blocked")) for chain in chains),
        "decisions": dict(decisions),
        "severities": dict(severities),
        "sequence_types": dict(Counter(str(chain.get("sequence_type") or "unknown") for chain in chains)),
    }
    if action_dir:
        static_evidence = [reports / name for name in ("static-scan.json", "static-eval.json", "rule-contract.json")]
        run_evidence = required + [action_dir / name for name in (
            "replay-process.json", "observations.jsonl", "resources.jsonl", "host-gateway.jsonl",
        )]
        if baseline_manifest:
            run_evidence.extend(baseline_dir / name for name in (
                "run.json", "replay-process.json", "observations.jsonl", "resources.jsonl", "host-gateway.jsonl",
            ))
        evidence_files = sorted(path.relative_to(root).as_posix() for path in static_evidence + run_evidence if path.is_file())
    else:
        evidence_files = sorted(
            [path.relative_to(root).as_posix() for path in reports.glob("*") if path.is_file()]
            + [path.relative_to(root).as_posix() for path in results.glob("*") if path.is_file()]
        )
    return {
        "schema_version": 1,
        "generated_at": datetime.now(UTC).isoformat(),
        "scope": "AgentRange non-invasive DefenseClaw adapter",
        "static": {
            "metrics": static_metrics,
            "evaluation": static_evaluation,
            "finding_count": len(static.get("findings", [])),
            "graph_edge_count": len(static.get("asset_edges", [])),
            "high_critical": sum(item.get("severity") in {"HIGH", "CRITICAL"} for item in static.get("findings", [])),
            "missed_labeled_risks": (static_evaluation.get("risk") or {}).get("missed", []),
        },
        "rules": {
            "passed": rules.get("passed"),
            "limit_ms_per_case": rules.get("limit_ms_per_case"),
            "results": rules.get("results", []),
        },
        "runtime": runtime_summary,
        "benchmark": benchmark,
        "benchmark_provenance": benchmark_provenance,
        "plan_traceability": traceability,
        "chains": representative_chains(chains),
        "recent_events": events[-20:] if action_dir else events[-200:],
        "evidence_index": evidence_files,
        "notes": [
            "Runtime evidence is read from DefenseClaw audit.db exports, not from AgentRange source modifications.",
            "AgentRange remains an unmodified traffic source; generated reports live in DefenseClaw project-side directories.",
            "Plan traceability checks repository artifact paths only; evidence-ready is not a hidden-set result.",
            ("Runtime and benchmark evidence is limited to the selected action/baseline pair."
             if action_dir else "Missing mode reports remain explicit in benchmark.missing_modes."),
        ],
    }


def to_markdown(report: dict[str, Any]) -> str:
    runtime = report["runtime"]
    static = report["static"]
    static_evaluation = static.get("evaluation") or {}
    benchmark = report.get("benchmark") or {}
    benchmark_provenance = report.get("benchmark_provenance") or {}
    traceability = report.get("plan_traceability") or {"counts": {}, "requirements": []}
    lines = [
        "# AgentRange DefenseClaw Report",
        "",
        f"Generated: {report['generated_at']}",
        "",
        "## Static Inventory",
        "",
        f"- Discovered assets: {(static.get('metrics') or {}).get('asset_found', 'not-run')}",
        f"- Inferred asset edges: {static.get('graph_edge_count', 0)}",
        f"- Findings: {static['finding_count']} (HIGH/CRITICAL: {static['high_critical']})",
        "",
    ]
    if static_evaluation:
        asset = static_evaluation.get("asset") or {}
        risk = static_evaluation.get("risk") or {}
        lines.extend([
            f"- Local labeled asset precision/recall: {asset.get('precision')} / {asset.get('recall')}",
            f"- Local labeled risk precision/recall: {risk.get('precision')} / {risk.get('recall')}",
            f"- Static evaluation scope: {static_evaluation.get('scope', 'unknown')}",
            "",
        ])
    lines.extend([
        "## Runtime Evidence",
        "",
        f"- Events: {runtime['event_count']}",
        f"- Sessions: {runtime['session_count']}",
        f"- Attack chains: {runtime['attack_chain_count']}",
        f"- Blocked chains: {runtime['blocked_chain_count']}",
        f"- Decisions: {json.dumps(runtime['decisions'], ensure_ascii=False)}",
        f"- Severities: {json.dumps(runtime['severities'], ensure_ascii=False)}",
        "",
        "## Benchmark",
        "",
    ])
    acceptance = benchmark.get("acceptance") or {}
    overall = benchmark.get("overall") or {}
    if overall:
        counts = overall.get("counts") or {}
        latency = overall.get("latency_ms") or {}
        inspect = overall.get("inspect_latency_ms") or {}
        availability = overall.get("inspection_availability") or {}
        resources = benchmark.get("resources") or {}
        lines.extend([
            f"- Confirmed blocks / false positives: {counts.get('tp')} / {counts.get('fp')}",
            f"- Normal business successes: {(overall.get('normal_business') or {}).get('success')} / {(overall.get('normal_business') or {}).get('total')}",
            f"- Unavailable inspections: {availability.get('unavailable_events')}",
            f"- End-to-end / inspection p95: {latency.get('p95')} / {inspect.get('p95')} ms",
            f"- Per-container CPU p95 increment: {resources.get('cpu_increment_pct')} percentage points",
            "",
        ])
    if acceptance:
        lines.extend(f"- {'PASS' if passed else 'WAIT/FAIL'}: {name}" for name, passed in acceptance.items())
    else:
        lines.append("- Benchmark summary not generated.")
    if benchmark_provenance:
        lines.extend(["", "### Benchmark Provenance", ""])
        lines.append(f"- Comparable mode set: {benchmark_provenance.get('comparable_mode_set', 'unknown')}")
        for note in benchmark_provenance.get("notes", []):
            lines.append(f"- {note}")
    lines.extend(["", "## Representative Chains", ""])
    for chain in report.get("chains", []):
        block_node = next((node for node in chain.get("nodes", []) if node.get("id") == chain.get("block_node_id")), {})
        lines.append(f"- `{chain.get('chain_id')}`: {'blocked' if chain.get('blocked') else 'allowed'}, {chain.get('sequence_type')}; evidence `{block_node.get('raw_ref') or 'none'}`")
        if block_node:
            location = " ".join(f"`{part}`" for part in (
                block_node.get("tool_name"), block_node.get("http_path"),
            ) if part)
            if location:
                lines.append(f"  - Tool/path: {location}")
            frames = block_node.get("app_frames") or []
            if frames:
                frame = frames[0]
                lines.append(f"  - Reported call site: `{frame.get('module')}.{frame.get('function')}:{frame.get('line')}` ({block_node.get('app_frames_source')})")
    lines.extend(["", "## Plan Traceability", ""])
    counts = traceability.get("counts") or {}
    lines.append(
        "- Evidence-ready: "
        f"{counts.get('evidence-ready', 0)}; implemented awaiting evidence: "
        f"{counts.get('implemented-awaiting-evidence', 0)}; not implemented: {counts.get('not-implemented', 0)}"
    )
    for row in traceability.get("requirements", []):
        lines.append(f"- {row['id']} [{row['status']}]: {row['title']}")
    lines.extend(["", "## Evidence Files", ""])
    lines.extend(f"- `{path}`" for path in report["evidence_index"])
    lines.extend(["", "## Notes", ""])
    lines.extend(f"- {note}" for note in report["notes"])
    return "\n".join(lines) + "\n"


# Compatibility with the zlq report tests and helpers.
def build(root: Path = ROOT) -> dict[str, Any]:
    return build_report(root)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--benchmark-run-dir", type=Path, help="Use one scored action/baseline replay and its scoped chain evidence")
    parser.add_argument("--json", type=Path)
    parser.add_argument("--markdown", type=Path)
    args = parser.parse_args()
    report = build_report(ROOT, args.benchmark_run_dir)
    default_dir = args.benchmark_run_dir.resolve() if args.benchmark_run_dir else REPORTS
    json_output = args.json or default_dir / "final-report.json"
    markdown_output = args.markdown or default_dir / "final-report.md"
    json_output.parent.mkdir(parents=True, exist_ok=True)
    markdown_output.parent.mkdir(parents=True, exist_ok=True)
    json_output.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    markdown_output.write_text(to_markdown(report), encoding="utf-8")
    print(json.dumps({"json": str(json_output), "markdown": str(markdown_output)}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
