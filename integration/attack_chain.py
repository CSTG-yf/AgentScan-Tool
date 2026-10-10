"""Build AgentRange attack-chain evidence from DefenseClaw audit events."""

from __future__ import annotations

import argparse
import json
import os
import sqlite3
from collections import defaultdict
from datetime import UTC, datetime, timedelta
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


def load_run_scope(run_dir: Path) -> tuple[tuple[datetime, datetime], set[str]]:
    process = json.loads((run_dir / "replay-process.json").read_text(encoding="utf-8"))
    manifest = json.loads((run_dir / "run.json").read_text(encoding="utf-8"))
    if process.get("returncode") != 0 or process.get("mode") != "action" or manifest.get("mode") != "action":
        raise ValueError("a completed action replay is required for scoped evidence")
    start = datetime.fromisoformat(process["started_at"].replace("Z", "+00:00")).astimezone(UTC)
    end = datetime.fromisoformat(process["finished_at"].replace("Z", "+00:00")).astimezone(UTC)
    if end <= start:
        raise ValueError("invalid replay window")
    observations = [
        json.loads(line)
        for line in (run_dir / "observations.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    ids = {str(row.get("instance_id") or "") for row in observations}
    if (not isinstance(manifest.get("total"), int) or manifest["total"] <= 0
            or len(observations) != manifest["total"] or len(ids) != manifest["total"]
            or "" in ids or any(row.get("mode") != "action" for row in observations)):
        raise ValueError("replay observations must contain one action row per manifest instance")
    return (start, end), ids


def load_audit_events(
    audit_db: Path,
    *,
    window: tuple[datetime, datetime] | None = None,
    instance_ids: set[str] | None = None,
) -> list[dict[str, Any]]:
    if not audit_db.exists():
        return []
    con = sqlite3.connect(audit_db)
    con.row_factory = sqlite3.Row
    window_clause = "AND timestamp >= ? AND timestamp < ?" if window else ""
    params = (
        (window[0] - timedelta(seconds=1)).strftime("%Y-%m-%dT%H:%M:%S"),
        (window[1] + timedelta(seconds=1)).strftime("%Y-%m-%dT%H:%M:%S"),
    ) if window else ()
    rows = con.execute(
        f"""
        SELECT id, timestamp, action, target, actor, details, structured_json,
               severity, connector, trace_id, session_id, destination_app,
               tool_name
        FROM audit_events
        WHERE (action LIKE 'agentrange-runtime-%'
           OR connector = 'agentrange'
           OR actor = 'defenseclaw-agentrange-sidecar')
        {window_clause}
        ORDER BY timestamp, id
        """,
        params,
    ).fetchall()
    con.close()
    events: list[dict[str, Any]] = []
    for row in rows:
        structured = parse_json(row["structured_json"])
        timestamp = str(row["timestamp"] or "")
        if window:
            try:
                observed_at = datetime.fromisoformat(timestamp.replace("Z", "+00:00")).astimezone(UTC)
            except ValueError:
                continue
            if not window[0] <= observed_at <= window[1]:
                continue
        instance_id = str(structured.get("instance_id") or row["session_id"] or structured.get("session_id") or "")
        if instance_ids is not None and instance_id not in instance_ids:
            continue
        action = str(row["action"] or "")
        stage = str(structured.get("stage") or action.removeprefix("agentrange-runtime-") or "unknown")
        event = {
            "event_id": row["id"],
            "timestamp": timestamp,
            "action": action,
            "stage": stage,
            "target": row["target"] or "",
            "actor": row["actor"] or "",
            "details": row["details"] or "",
            "severity": row["severity"] or structured.get("severity") or "INFO",
            "connector": row["connector"] or structured.get("connector") or "agentrange",
            "trace_id": row["trace_id"] or structured.get("trace_id") or "",
            "session_id": row["session_id"] or structured.get("session_id") or "",
            "instance_id": instance_id,
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
                    "prompt_excerpt": str(event.get("prompt") or "")[:500],
                    "request_excerpt": str(event.get("request_body") or "")[:500],
                    "http_method": event.get("http_method") or "",
                    "http_path": event.get("http_path") or "",
                    "app_frames": event.get("app_frames") or [],
                    "app_frames_source": event.get("app_frames_source") or "",
                }
            )
            if index > 1:
                edges.append({
                    "from": f"n{index - 1}", "to": node_id,
                    "relation": "observed_before", "evidence_level": "time_window_inference",
                })
        block_nodes = [node for node in nodes if node["decision"] == "block"]
        if block_nodes:
            block_node_id = max(block_nodes, key=lambda node: (
                node["stage"] == "block",
                bool(node["http_path"] or node["tool_name"]),
                bool(node["request_excerpt"] or node["prompt_excerpt"]),
                bool(node["app_frames"]),
            ))["id"]
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
    parser.add_argument("--run-dir", type=Path, help="Limit evidence to a completed action replay")
    parser.add_argument("--events-output", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    audit_db = args.audit_db or defenseclaw_home() / "audit.db"
    run_dir = args.run_dir.resolve() if args.run_dir else None
    if run_dir and not audit_db.is_file():
        raise FileNotFoundError(audit_db)
    window, instance_ids = load_run_scope(run_dir) if run_dir else (None, None)
    events_output = args.events_output or (run_dir / "runtime-events.jsonl" if run_dir else DEFAULT_REPORTS / "runtime-events.jsonl")
    output = args.output or (run_dir / "attack-chains.json" if run_dir else DEFAULT_REPORTS / "attack-chains.json")
    events = load_audit_events(audit_db, window=window, instance_ids=instance_ids)
    write_jsonl(events_output, events)
    chains = build_chains(events)
    result = {
        "schema_version": 1,
        "source": str(audit_db),
        "event_count": len(events),
        "chains": chains,
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({"output": str(output), "events": len(events), "chains": len(chains)}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
