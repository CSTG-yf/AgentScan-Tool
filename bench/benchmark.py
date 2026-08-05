"""Summarize AgentRange DefenseClaw runtime evidence."""

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


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    rows = []
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


def summarize_events(events: list[dict[str, Any]]) -> dict[str, Any]:
    decisions = Counter(str(event.get("decision") or "unknown") for event in events)
    severities = Counter(str(event.get("severity") or "INFO") for event in events)
    stages = Counter(str(event.get("stage") or "unknown") for event in events)
    tools = Counter(str(event.get("tool_name") or event.get("mcp_server") or "") for event in events)
    tools.pop("", None)
    sessions = {str(event.get("session_id") or event.get("trace_id") or event.get("event_id")) for event in events}
    latencies = [int(event["latency_ms"]) for event in events if isinstance(event.get("latency_ms"), int)]
    return {
        "schema_version": 1,
        "generated_at": datetime.now(UTC).isoformat(),
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
            "max": max(latencies) if latencies else None,
            "avg": round(sum(latencies) / len(latencies), 2) if latencies else None,
        },
        "acceptance": {
            "runtime_events_present": len(events) > 0,
            "agentrange_connector_seen": any(str(event.get("connector")) == "agentrange" for event in events),
            "attack_chain_input_ready": (REPORTS / "attack-chains.json").exists(),
        },
    }


def summarize(output: Path) -> int:
    events = load_jsonl(REPORTS / "runtime-events.jsonl")
    report = summarize_events(events)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({"output": str(output), "events": report["event_count"]}, ensure_ascii=False))
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command")
    summarize_parser = subparsers.add_parser("summarize", help="Write bench/results/summary.json")
    summarize_parser.add_argument("--output", type=Path, default=RESULTS / "summary.json")
    args = parser.parse_args()
    if args.command in {None, "summarize"}:
        return summarize(args.output if hasattr(args, "output") else RESULTS / "summary.json")
    parser.error(f"unknown command: {args.command}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
