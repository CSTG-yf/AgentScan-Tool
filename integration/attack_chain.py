"""Build AgentRange attack-chain evidence from DefenseClaw audit events."""

from __future__ import annotations

import argparse
import json
import os
import sqlite3
from collections import defaultdict
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_REPORTS = ROOT / "integration" / "reports"


def defenseclaw_home(root: Path = ROOT) -> Path:
    configured = os.getenv("DEFENSECLAW_HOME")
    if configured:
        return Path(configured).expanduser()
    env_file = root / ".env"
    if env_file.exists():
        for line in env_file.read_text(encoding="utf-8", errors="replace").splitlines():
            if line.startswith("DEFENSECLAW_HOME="):
                return Path(line.split("=", 1)[1].strip().strip('"')).expanduser()
    return root / ".defenseclaw-home"


def parse_json(raw: str | None) -> dict[str, Any]:
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return {}
    if not isinstance(parsed, dict):
        return {}
    nested = parsed.get("structured")
    if isinstance(nested, dict):
        return nested
    return parsed


def decision_from(row: sqlite3.Row, structured: dict[str, Any]) -> str:
    decision = str(structured.get("decision") or "").lower()
    if decision:
        return decision
    details = str(row["details"] or "").lower()
    if "decision=block" in details:
        return "block"
    if "decision=allow" in details:
        return "allow"
    if "inspect_unavailable" in details:
        return "inspect_unavailable"
    return "unknown"


def load_audit_events(audit_db: Path) -> list[dict[str, Any]]:
    if not audit_db.exists():
        return []
    con = sqlite3.connect(audit_db)
    con.row_factory = sqlite3.Row
    rows = con.execute(
        """
        SELECT id, timestamp, action, target, actor, details, structured_json,
               severity, connector, trace_id, session_id, destination_app,
               tool_name
        FROM audit_events
        WHERE action LIKE 'agentrange-runtime-%'
           OR connector = 'agentrange'
           OR actor = 'defenseclaw-agentrange-sidecar'
        ORDER BY timestamp, id
        """
    ).fetchall()
    con.close()
    events: list[dict[str, Any]] = []
    for row in rows:
        structured = parse_json(row["structured_json"])
        action = str(row["action"] or "")
        stage = str(structured.get("stage") or action.removeprefix("agentrange-runtime-") or "unknown")
        event = {
            "event_id": row["id"],
            "timestamp": row["timestamp"],
            "action": action,
            "stage": stage,
            "target": row["target"] or "",
            "actor": row["actor"] or "",
            "details": row["details"] or "",
            "severity": row["severity"] or structured.get("severity") or "INFO",
            "connector": row["connector"] or structured.get("connector") or "agentrange",
            "trace_id": row["trace_id"] or structured.get("trace_id") or "",
            "session_id": row["session_id"] or structured.get("session_id") or "",
            "instance_id": structured.get("instance_id") or row["session_id"] or structured.get("session_id") or "",
            "destination_app": row["destination_app"] or structured.get("destination") or "",
            "tool_name": row["tool_name"] or structured.get("tool_name") or "",
            "mcp_server": structured.get("mcp_server") or "",
            "proxy_kind": structured.get("proxy_kind") or "",
            "http_method": structured.get("http_method") or "",
            "http_path": structured.get("http_path") or "",
            "app_frames": structured.get("app_frames") if isinstance(structured.get("app_frames"), list) else [],
            "app_frames_source": structured.get("app_frames_source") or "",
            "decision": decision_from(row, structured),
            "reason": structured.get("reason") or "",
            "latency_ms": structured.get("latency_ms"),
            "prompt": str(structured.get("prompt") or "")[:500],
            "request_body": str(structured.get("request_body") or "")[:500],
            "response_body": str(structured.get("response_body") or "")[:500],
            "raw_ref": f"audit.db:{row['id']}",
        }
        events.append(event)
    return events


def write_jsonl(path: Path, events: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for event in events:
            handle.write(json.dumps(event, ensure_ascii=False, sort_keys=True) + "\n")


def classify_sequence(events: list[dict[str, Any]]) -> str:
    joined = " ".join(
        str(event.get(field, ""))
        for event in events
        for field in ("stage", "destination_app", "tool_name", "mcp_server", "http_path", "request_body", "prompt")
    ).casefold()
    if "langflow" in joined:
        return "langflow_ingress_or_framework_exploit"
    if "tenant" in joined and any(marker in joined for marker in ("globex", "acme", '"*"')):
        return "identity_scope_or_cross_tenant_access"
    if any(marker in joined for marker in (".env", "/etc/shadow", "/proc/self/environ")):
        return "sensitive_file_access"
    if any(marker in joined for marker in ("curl", "wget", "| sh", "shell", "cron")):
        return "command_execution_or_egress"
    if any(event.get("tool_name") for event in events):
        return "agent_tool_activity"
    return "runtime_observation"


def pollution_source(events: list[dict[str, Any]], sequence_type: str) -> str | None:
    if not events:
        return None
    if sequence_type.startswith("langflow"):
        return "langflow_http_request"
    first = events[0]
    for field in ("prompt", "request_body", "http_path", "details"):
        value = str(first.get(field) or "").strip()
        if value:
            return value[:240]
    return None


def unexecuted_side_effects(sequence_type: str, blocked: bool) -> list[str]:
    if not blocked:
        return []
    if sequence_type == "sensitive_file_access":
        return ["subsequent credential disclosure or sync action"]
    if sequence_type == "command_execution_or_egress":
        return ["command execution or outbound callback"]
    if sequence_type == "identity_scope_or_cross_tenant_access":
        return ["cross-tenant data read"]
    if sequence_type == "langflow_ingress_or_framework_exploit":
        return ["forwarding to the vulnerable Langflow endpoint"]
    return ["downstream AgentRange side effect"]


def event_summary(event: dict[str, Any]) -> str:
    pieces = [
        str(event.get("stage") or "unknown"),
        str(event.get("destination_app") or event.get("proxy_kind") or ""),
        str(event.get("tool_name") or event.get("mcp_server") or ""),
        str(event.get("decision") or ""),
    ]
    return " ".join(piece for piece in pieces if piece).strip()


def build_chains(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for event in events:
        key = str(event.get("instance_id") or event.get("session_id") or event.get("trace_id") or event.get("event_id"))
        grouped[key].append(event)
    chains: list[dict[str, Any]] = []
    for key in sorted(grouped):
        rows = grouped[key]
        nodes = []
        edges = []
        block_node_id = None
        sequence_type = classify_sequence(rows)
        for index, event in enumerate(rows, 1):
            node_id = f"n{index}"
            if event.get("decision") == "block" and block_node_id is None:
                block_node_id = node_id
            nodes.append(
                {
                    "id": node_id,
                    "timestamp": event.get("timestamp"),
                    "stage": event.get("stage"),
                    "asset_id": event.get("destination_app") or event.get("proxy_kind") or "agentrange",
                    "summary": event_summary(event),
                    "evidence_level": "direct" if event.get("raw_ref") else "time_window_inference",
                    "decision": event.get("decision"),
                    "severity": event.get("severity"),
                    "raw_ref": str(event.get("raw_ref") or ""),
                    "tool_name": event.get("tool_name"),
                    "reason": event.get("reason"),
                    "app_frames": event.get("app_frames") or [],
                    "app_frames_source": event.get("app_frames_source") or "",
                }
            )
            if index > 1:
                edges.append({
                    "from": f"n{index - 1}", "to": node_id,
                    "relation": "observed_before", "evidence_level": "time_window_inference",
                })
        chains.append(
            {
                "chain_id": f"chain:{key}",
                "instance_id": key,
                "session_id": rows[0].get("session_id") or key,
                "trace_id": rows[0].get("trace_id") or key,
                "blocked": block_node_id is not None,
                "block_node_id": block_node_id,
                "pollution_source": pollution_source(rows, sequence_type),
                "sequence_type": sequence_type,
                "unexecuted_side_effects": unexecuted_side_effects(sequence_type, block_node_id is not None),
                "nodes": nodes,
                "edges": edges,
                "evidence_summary": f"{len(nodes)} events; block={block_node_id or 'none'}",
            }
        )
    return chains


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--audit-db", type=Path, default=None)
    parser.add_argument("--events-output", type=Path, default=DEFAULT_REPORTS / "runtime-events.jsonl")
    parser.add_argument("--output", type=Path, default=DEFAULT_REPORTS / "attack-chains.json")
    args = parser.parse_args()

    audit_db = args.audit_db or defenseclaw_home() / "audit.db"
    events = load_audit_events(audit_db)
    write_jsonl(args.events_output, events)
    chains = build_chains(events)
    result = {
        "schema_version": 1,
        "source": str(audit_db),
        "event_count": len(events),
        "chains": chains,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({"output": str(args.output), "events": len(events), "chains": len(chains)}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
