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


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    events: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line.strip():
            continue
        try:
            parsed = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(parsed, dict):
            events.append(parsed)
    return events


def build_report(root: Path = ROOT) -> dict[str, Any]:
    reports = root / "integration" / "reports"
    results = root / "bench" / "results"
    events = read_jsonl(reports / "runtime-events.jsonl")
    chains_doc = read_json(reports / "attack-chains.json", {"chains": []})
    static = read_json(reports / "static-scan.json", {})
    rules = read_json(reports / "rule-contract.json", {})
    benchmark = read_json(results / "summary.json", {})
    chains = chains_doc.get("chains", [])
    decisions = Counter(str(event.get("decision") or "unknown") for event in events)
    severities = Counter(str(event.get("severity") or "INFO") for event in events)
    sessions = {
        event.get("session_id") or event.get("trace_id") or event.get("event_id")
        for event in events
    }
    traceability = evaluate_requirements(root)
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
            "finding_count": len(static.get("findings", [])),
            "high_critical": sum(item.get("severity") in {"HIGH", "CRITICAL"} for item in static.get("findings", [])),
            "missing_required_risks": static.get("missing_required_risks", []),
            "benign_control_violations": static.get("benign_control_violations", []),
        },
        "rules": {
            "passed": rules.get("passed"),
            "limit_ms_per_case": rules.get("limit_ms_per_case"),
            "results": rules.get("results", []),
        },
        "runtime": runtime_summary,
        "benchmark": benchmark,
        "plan_traceability": traceability,
        "chains": chains[:100],
        "recent_events": events[-200:],
        "evidence_index": evidence_files,
        "notes": [
            "Runtime evidence is read from DefenseClaw audit.db exports, not from AgentRange source modifications.",
            "AgentRange remains an unmodified traffic source; generated reports live in DefenseClaw project-side directories.",
            "Missing mode reports remain explicit in benchmark.missing_modes.",
            "If runtime event_count is 0, run the AgentRange adapter overlay after exporting the DefenseClaw gateway token.",
        ],
    }


def to_markdown(report: dict[str, Any]) -> str:
    runtime = report["runtime"]
    static = report["static"]
    benchmark = report.get("benchmark") or {}
    traceability = report.get("plan_traceability") or {"counts": {}, "requirements": []}
    lines = [
        "# AgentRange DefenseClaw Report",
        "",
        f"Generated: {report['generated_at']}",
        "",
        "## Static Inventory",
        "",
        f"- Asset coverage: {(static.get('metrics') or {}).get('asset_coverage', 'not-run')}",
        f"- Required risk recall: {(static.get('metrics') or {}).get('risk_recall', 'not-run')}",
        f"- Findings: {static['finding_count']} (HIGH/CRITICAL: {static['high_critical']})",
        "",
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
    ]
    acceptance = benchmark.get("acceptance") or {}
    if acceptance:
        lines.extend(f"- {'PASS' if passed else 'WAIT/FAIL'}: {name}" for name, passed in acceptance.items())
    else:
        lines.append("- Benchmark summary not generated.")
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
    parser.add_argument("--json", type=Path, default=REPORTS / "final-report.json")
    parser.add_argument("--markdown", type=Path, default=REPORTS / "final-report.md")
    args = parser.parse_args()
    report = build_report(ROOT)
    args.json.parent.mkdir(parents=True, exist_ok=True)
    args.json.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    args.markdown.write_text(to_markdown(report), encoding="utf-8")
    print(json.dumps({"json": str(args.json), "markdown": str(args.markdown)}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
