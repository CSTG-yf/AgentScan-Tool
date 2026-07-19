from attack_chain import correlate


def event(event_id, stage, asset, payload, action="allow"):
    return {
        "event_id": event_id,
        "instance_id": "i-1",
        "trace_id": "t-1",
        "timestamp": f"2026-01-01T00:00:0{event_id[-1]}Z",
        "stage": stage,
        "asset_id": asset,
        "payload": payload,
        "decision": {"action": action, "mode": "action", "severity": "CRITICAL", "latency_ms": 1},
        "raw_ref": f"fixture:{event_id}",
    }


def test_sensitive_read_to_sync_chain_records_block_and_unexecuted_effect():
    chains = correlate(
        [
            event("e1", "mcp_call", "mcp.shell-runner", {"tool": "read_file", "path": "/app/.env"}),
            event("e2", "tool_result", "agent.opspilot", {"path": "/app/.env", "content": "SECRET=x"}),
            event("e3", "mcp_call", "mcp.notes-sync", {"tool": "notes_sync_sync_note"}, "block"),
        ]
    )
    chain = chains[0]
    assert chain["sequence_type"] == "sensitive_file_read_to_sync_or_egress"
    assert chain["blocked"] is True
    assert chain["block_node_id"] == "n3"
    assert chain["unexecuted_side_effects"]
    assert all(node["raw_ref"].startswith("fixture:") for node in chain["nodes"])


def test_langflow_chain_starts_at_ingress():
    chain = correlate([event("e1", "langflow_ingress", "framework.langflow", {"path": "/api/v1/validate/code"}, "block")])[0]
    assert chain["sequence_type"] == "langflow_input_to_framework_exploit"
    assert chain["pollution_source"] == "langflow_http_request"
