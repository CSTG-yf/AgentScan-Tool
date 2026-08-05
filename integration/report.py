"""Aggregate AgentRange non-invasive DefenseClaw evidence."""

from __future__ import annotations

import argparse
import json
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

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


def build_report() -> dict[str, Any]:
    events = read_jsonl(REPORTS / "runtime-events.jsonl")
    chains_doc = read_json(REPORTS / "attack-chains.json", {"chains": []})
    benchmark = read_json(RESULTS / "summary.json", {})
    chains = chains_doc.get("chains", [])
    decisions = Counter(str(event.get("decision") or "unknown") for event in events)
    severities = Counter(str(event.get("severity") or "INFO") for event in events)
    sessions = {
        event.get("session_id") or event.get("trace_id") or event.get("event_id")
        for event in events
    }
    return {
        "schema_version": 1,
        "generated_at": datetime.now(UTC).isoformat(),
        "scope": "AgentRange non-invasive DefenseClaw adapter",
        "runtime": {
            "event_count": len(events),
            "session_count": len(sessions),
            "attack_chain_count": len(chains),
            "blocked_chain_count": sum(bool(chain.get("blocked")) for chain in chains),
            "decisions": dict(decisions),
            "severities": dict(severities),
            "sequence_types": dict(Counter(str(chain.get("sequence_type") or "unknown") for chain in chains)),
        },
        "benchmark": benchmark,
        "chains": chains[:100],
        "recent_events": events[-200:],
        "evidence_index": sorted(path.relative_to(ROOT).as_posix() for path in REPORTS.glob("*") if path.is_file()),
        "notes": [
            "Runtime evidence is read from DefenseClaw audit.db, not from AgentRange source files.",
            "AgentRange remains an unmodified traffic source; generated reports live in project-side directories.",
            "If event_count is 0, restart Compose after exporting DEFENSECLAW_GATEWAY_TOKEN to the sidecars.",
        ],
    }


def to_markdown(report: dict[str, Any]) -> str:
    runtime = report["runtime"]
    lines = [
        "# AgentRange DefenseClaw Report",
        "",
        f"Generated: {report['generated_at']}",
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
        "## Evidence Files",
        "",
    ]
    lines.extend(f"- `{path}`" for path in report["evidence_index"])
    lines.extend(["", "## Notes", ""])
    lines.extend(f"- {note}" for note in report["notes"])
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", type=Path, default=REPORTS / "final-report.json")
    parser.add_argument("--markdown", type=Path, default=REPORTS / "final-report.md")
    args = parser.parse_args()
    report = build_report()
    args.json.parent.mkdir(parents=True, exist_ok=True)
    args.json.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    args.markdown.write_text(to_markdown(report), encoding="utf-8")
    print(json.dumps({"json": str(args.json), "markdown": str(args.markdown)}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
