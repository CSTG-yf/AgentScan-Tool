import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from gateway_enforcement import collect_enforcements, enforcement_observations
from run_store import EvaluationRun


def pre(session, call, *, event_id=10, mode="action", tool="query", server="mcp-customer-db", kind="mcp"):
    return {
        "id": event_id, "session_id": session, "event_source": "guardrail",
        "tool_name": tool, "mcp_server": server,
        "attributes": {"phase": "pre", "inspection_status": "complete", "action": "block",
                       "inspection_mode": mode, "call_id": call, "proxy_kind": kind},
    }


def result(session, call, *, event_id=11, outcome="rejected"):
    return {
        "id": event_id, "session_id": session, "event_source": "proxy", "outcome": "blocked",
        "attributes": {"phase": "result", "operation_result": outcome, "call_id": call},
    }


class FakeClient:
    def __init__(self, pages):
        self.pages = pages
        self.calls = 0

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def get(self, *_args, **_kwargs):
        value = self.pages[self.calls]
        self.calls += 1
        response = Mock()
        response.json.return_value = value
        return response


class GatewayEnforcementTests(unittest.TestCase):
    def test_only_confirmed_pre_rejection_counts(self):
        truth = [
            {"instance_id": "a", "scenario": "C2-A"},
            {"instance_id": "b", "scenario": "C2-D"},
            {"instance_id": "c", "scenario": "C2-A"},
        ]
        rows = enforcement_observations(truth, [
            pre("a", "c1"), result("a", "c1"),
            pre("b", "c2", event_id=20, tool="sync_note", server="mcp-notes-sync"), result("b", "c2", event_id=21),
            pre("c", "c3", event_id=30, mode="observe"), result("c", "c3", event_id=31),
        ])
        self.assertEqual([row["enforced_block"] for row in rows], [True, True, None])
        self.assertEqual(rows[0]["evidence_refs"], ["event:10", "event:11"])

    def test_post_response_block_and_unrelated_tool_do_not_count(self):
        truth = [{"instance_id": "a", "scenario": "C2-A"}]
        rows = enforcement_observations(truth, [
            pre("a", "c1", tool="lookup", server="mcp-threat-intel"), result("a", "c1"),
            pre("a", "c2", event_id=20), result("a", "c2", event_id=21, outcome="response_blocked"),
        ])
        self.assertIsNone(rows[0]["enforced_block"])

    def test_collects_gateway_event_snapshot(self):
        with tempfile.TemporaryDirectory() as root:
            run = EvaluationRun.create(Path(root), [{"instance_id": "a", "label": "attack", "scenario": "C2-A"}], {})
            run.save_corpus([{"instance_id": "a"}], {})
            run.start_mode("baseline")
            run.record_replay("baseline", 1)
            events = [pre("a", "c1"), result("a", "c1")]
            with patch("gateway_enforcement.httpx.Client", return_value=FakeClient([{"items": events, "total": 2}])):
                rows = collect_enforcements(run.path, "baseline", token="SECRET")
            self.assertTrue(rows[0]["enforced_block"])
            saved = (run.path / "baseline-gateway-events.json").read_text(encoding="utf-8")
            self.assertNotIn("SECRET", saved)
            self.assertEqual(json.loads(saved)["count"], 2)


if __name__ == "__main__":
    unittest.main()
