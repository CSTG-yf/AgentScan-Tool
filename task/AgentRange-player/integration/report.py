"""Aggregate AgentRange static, runtime, chain, and benchmark evidence."""

from __future__ import annotations

import argparse
import json
from datetime import UTC, datetime
from pathlib import Path

from requirements_contract import evaluate as evaluate_requirements


def read_json(path: Path, default):
    if not path.exists():
        return default
    return json.loads(path.read_text(encoding="utf-8"))


def build(root: Path) -> dict:
    reports = root / "integration" / "reports"
    static = read_json(reports / "static-scan.json", {})
    chains = read_json(reports / "attack-chains.json", {"chains": []})
    benchmark = read_json(root / "bench" / "results" / "summary.json", {})
    chain_rows = chains.get("chains", [])
    requirements = evaluate_requirements(root.parents[1])
    evidence_files = sorted(path.relative_to(root).as_posix() for path in reports.glob("*") if path.is_file())
    return {
        "schema_version": 1,
        "generated_at": datetime.now(UTC).isoformat(),
        "scope": "AgentRange OpsPilot MVP",
        "plan_traceability": requirements,
        "static": {
            "metrics": static.get("metrics", {}),
            "finding_count": len(static.get("findings", [])),
            "high_critical": sum(item.get("severity") in {"HIGH", "CRITICAL"} for item in static.get("findings", [])),
            "missing_required_risks": static.get("missing_required_risks", []),
        },
        "runtime": {
            "attack_chains": len(chain_rows),
            "blocked_chains": sum(bool(item.get("blocked")) for item in chain_rows),
            "sequence_types": sorted({item.get("sequence_type", "unknown") for item in chain_rows}),
        },
        "benchmark": benchmark,
        "evidence_index": evidence_files,
        "degradation_notes": [
            "Missing mode reports remain explicit in benchmark.missing_modes.",
            "Inspection network failures are recorded as invalid instances and integration-fail-open/closed decisions.",
            "No detection evidence is sourced from /admin/trajectories.",
        ],
    }


def to_markdown(report: dict) -> str:
    static = report["static"]
    runtime = report["runtime"]
    benchmark = report.get("benchmark") or {}
    acceptance = benchmark.get("acceptance") or {}
    traceability = report["plan_traceability"]
    lines = [
        "# AgentRange security validation report",
        "",
        f"Generated: {report['generated_at']}",
        "",
        "## Static inventory and risk",
        "",
        f"- Asset coverage: {static.get('metrics', {}).get('asset_coverage', 'not-run')}",
        f"- Required risk recall: {static.get('metrics', {}).get('risk_recall', 'not-run')}",
        f"- Findings: {static['finding_count']} (HIGH/CRITICAL: {static['high_critical']})",
        "",
        "## Runtime attack chains",
        "",
        f"- Chains: {runtime['attack_chains']}",
        f"- Blocked chains: {runtime['blocked_chains']}",
        f"- Sequence types: {', '.join(runtime['sequence_types']) or 'not-run'}",
        "",
        "## Acceptance",
        "",
    ]
    if acceptance:
        lines.extend(f"- {'PASS' if passed else 'FAIL'}: {name}" for name, passed in acceptance.items())
    else:
        lines.append("- Benchmark summary not generated.")
    lines.extend(["", "## Plan traceability", ""])
    counts = traceability["counts"]
    lines.append(
        "- Evidence-ready: "
        f"{counts['evidence-ready']}; implemented awaiting evidence: "
        f"{counts['implemented-awaiting-evidence']}; not implemented: {counts['not-implemented']}"
    )
    lines.extend(f"- {row['id']} [{row['status']}]: {row['title']}" for row in traceability["requirements"])
    lines.extend(["", "## Evidence index", ""])
    lines.extend(f"- `{path}`" for path in report["evidence_index"])
    lines.extend(["", "## Degradation and boundaries", ""])
    lines.extend(f"- {note}" for note in report["degradation_notes"])
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--json", type=Path)
    parser.add_argument("--markdown", type=Path)
    args = parser.parse_args()
    root = args.root.resolve()
    json_path = args.json or root / "integration" / "reports" / "final-report.json"
    markdown_path = args.markdown or root / "integration" / "reports" / "final-report.md"
    report = build(root)
    json_path.parent.mkdir(parents=True, exist_ok=True)
    json_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    markdown_path.write_text(to_markdown(report), encoding="utf-8")
    print(json.dumps({"json": str(json_path), "markdown": str(markdown_path)}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
