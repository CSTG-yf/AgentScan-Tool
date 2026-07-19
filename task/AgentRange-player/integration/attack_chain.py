"""Build explainable AttackChain DAGs from runtime evidence JSONL."""

from __future__ import annotations

import argparse
import json
from collections import defaultdict
from pathlib import Path


def load_events(paths: list[Path]) -> list[dict]:
    events = []
    for path in paths:
        if not path.exists():
            continue
        for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if not line.strip():
                continue
            event = json.loads(line)
            event["raw_ref"] = f"{path.as_posix()}:{line_number}"
            events.append(event)
    return sorted(events, key=lambda item: (item.get("timestamp", ""), item.get("event_id", "")))


def compact_payload(event: dict) -> str:
    return json.dumps(event.get("payload"), ensure_ascii=False, sort_keys=True)[:500]


def classify_sequence(events: list[dict]) -> str:
    joined = " ".join(compact_payload(item) for item in events).casefold()
    if events and events[0].get("stage") == "langflow_ingress":
        return "langflow_input_to_framework_exploit"
    if "tenant" in joined and any(marker in joined for marker in ('"*"', "globex", "requested_tenant")):
        return "identity_scope_to_cross_tenant_query"
    if any(marker in joined for marker in (".env", "/etc/shadow", "/proc/self/environ")) and any(marker in joined for marker in ("notes_sync", "sync_note", "curl", "http://")):
        return "sensitive_file_read_to_sync_or_egress"
    if any(marker in joined for marker in ("curl", "wget", "shell=true", "shell_runner", "debug_exec")):
        return "external_content_to_command_execution"
    return "runtime_risk_sequence"


def build_chain(instance_id: str, events: list[dict]) -> dict:
    nodes = []
    edges = []
    block_node_id = None
    for index, event in enumerate(events, 1):
        node_id = f"n{index}"
        verdict = event.get("decision") or {}
        summary = f"{event.get('stage')} {event.get('tool', '')} {verdict.get('action', '')}".strip()
        nodes.append(
            {
                "id": node_id,
                "stage": event.get("stage", "unknown"),
                "asset_id": event.get("asset_id", "unknown"),
                "summary": summary,
                "evidence_level": "direct",
                "raw_ref": event.get("raw_ref", "runtime:unknown"),
                "decision": verdict,
            }
        )
        if verdict.get("action") == "block" and block_node_id is None:
            block_node_id = node_id
        if index > 1:
            edges.append({"from": f"n{index - 1}", "to": node_id, "relation": "observed_before", "evidence_level": "direct"})

    sequence_type = classify_sequence(events)
    first_payload = compact_payload(events[0]) if events else ""
    pollution_source = "langflow_http_request" if sequence_type.startswith("langflow_") else (first_payload[:240] or None)
    unexecuted = []
    if block_node_id:
        if sequence_type == "sensitive_file_read_to_sync_or_egress":
            unexecuted.append("subsequent sync or egress action")
        elif sequence_type == "external_content_to_command_execution":
            unexecuted.append("command execution")
        elif sequence_type == "identity_scope_to_cross_tenant_query":
            unexecuted.append("cross-tenant database read")
        elif sequence_type.startswith("langflow_"):
            unexecuted.append("forwarding to vulnerable Langflow endpoint")
    trace_id = str(events[0].get("trace_id") if events else instance_id)
    return {
        "chain_id": f"chain:{instance_id}",
        "instance_id": instance_id,
        "trace_id": trace_id,
        "blocked": block_node_id is not None,
        "block_node_id": block_node_id,
        "pollution_source": pollution_source,
        "sequence_type": sequence_type,
        "unexecuted_side_effects": unexecuted,
        "nodes": nodes,
        "edges": edges,
        "evidence_summary": f"{len(nodes)} direct events; sequence={sequence_type}; block={block_node_id or 'none'}",
    }


def correlate(events: list[dict]) -> list[dict]:
    grouped = defaultdict(list)
    for event in events:
        grouped[str(event.get("instance_id") or event.get("trace_id") or "unknown")].append(event)
    return [build_chain(instance_id, grouped[instance_id]) for instance_id in sorted(grouped)]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("inputs", nargs="*", type=Path)
    parser.add_argument("--output", type=Path, default=Path(__file__).with_name("reports") / "attack-chains.json")
    args = parser.parse_args()
    inputs = args.inputs or sorted((Path(__file__).with_name("reports")).glob("*-events.jsonl"))
    chains = correlate(load_events(inputs))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps({"chains": chains}, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({"output": str(args.output), "chains": len(chains), "blocked": sum(item["blocked"] for item in chains)}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
