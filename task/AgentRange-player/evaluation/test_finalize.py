import json
import tempfile
import unittest
from pathlib import Path

from finalize import _target_absent, finalize_mode
from gateway_enforcement import enforcement_observations
from mcp_probe import SERVICES
from run_store import EvaluationRun


class FinalizeTests(unittest.TestCase):
    def test_target_attempt_prevents_absence_proof(self):
        after = {
            "mcp-customer-db": {"items": [{"instance_id": "a", "tool": "query", "facts": {"tenant": "globex"}}]},
            "mcp-notes-sync": {"items": []},
            "mcp-shell-runner": {"items": []},
        }
        self.assertFalse(_target_absent("C2-A", "a", after))
        self.assertFalse(_target_absent("C2-B", "a", after))

    def make_run(self, root):
        run = EvaluationRun.create(Path(root), [
            {"instance_id": "a", "label": "attack", "scenario": "C2-A"},
            {"instance_id": "b", "label": "benign", "scenario": "B-RD"},
        ], {})
        run.save_corpus([{"instance_id": "a"}, {"instance_id": "b"}], {})
        run.start_mode("baseline")
        run.record_replay("baseline", 2, mcp_journal_continuous=True)
        journal = {service: {"boot_id": "boot-1", "high_water_seq": 0, "dropped": 0, "items": []} for service in SERVICES}
        (run.path / "baseline-mcp-before.json").write_text(json.dumps(journal), encoding="utf-8")
        (run.path / "baseline-mcp-after.json").write_text(json.dumps(journal), encoding="utf-8")
        (run.path / "baseline-receipts.jsonl").write_text(
            json.dumps({"instance_id": "a", "status": "http_error", "http_status": 403}) + "\n" +
            json.dumps({"instance_id": "b", "status": "completed", "http_status": 200}) + "\n",
            encoding="utf-8",
        )
        (run.path / "baseline-detection-observations.json").write_text(json.dumps([
            {"instance_id": "a", "detected": True, "evidence_refs": ["detection:d1"], "detection_scope_complete": False},
            {"instance_id": "b", "detected": None, "evidence_refs": [], "detection_scope_complete": False},
        ]), encoding="utf-8")
        started_at = run.manifest()["modes"]["baseline"]["started_at"]
        (run.path / "baseline-gateway-detections.json").write_text(json.dumps({"start_time": started_at, "end_time": started_at, "items": [
            {"session_id": "a", "detection_id": "d1"},
        ]}), encoding="utf-8")
        (run.path / "baseline-effect-observations.json").write_text(json.dumps([
            {"instance_id": "a", "effect": "unknown", "effect_evidence_ref": None},
            {"instance_id": "b", "effect": "unknown", "effect_evidence_ref": None},
        ]), encoding="utf-8")
        return run

    def test_http_block_does_not_become_enforced_block(self):
        with tempfile.TemporaryDirectory() as root:
            run = self.make_run(root)
            report = finalize_mode(run.path, "baseline")
            self.assertEqual(report["counts"]["TP"], 1)
            self.assertEqual(report["counts"]["effective_blocks"], 0)
            self.assertIsNone(report["metrics"]["effective_block_rate"])
            self.assertIsNone(report["metrics"]["normal_business_success_rate"])
            observations = json.loads((run.path / "baseline-observations.json").read_text(encoding="utf-8"))
            self.assertNotIn("enforced_block", observations[0])
            self.assertNotIn("business_completed", observations[1])

    def test_missing_instance_evidence_rejects_finalization(self):
        with tempfile.TemporaryDirectory() as root:
            run = self.make_run(root)
            (run.path / "baseline-effect-observations.json").write_text(
                json.dumps([{"instance_id": "a", "effect": "unknown"}]), encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "does not match"):
                finalize_mode(run.path, "baseline")
            self.assertEqual(run.manifest()["modes"]["baseline"]["status"], "running")

    def test_partial_evidence_cannot_inject_block_or_business_success(self):
        with tempfile.TemporaryDirectory() as root:
            run = self.make_run(root)
            path = run.path / "baseline-effect-observations.json"
            effects = json.loads(path.read_text(encoding="utf-8"))
            effects[0]["enforced_block"] = True
            path.write_text(json.dumps(effects), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "unsupported fields"):
                finalize_mode(run.path, "baseline")

    def test_action_effective_block_needs_rejection_and_target_absence(self):
        with tempfile.TemporaryDirectory() as root:
            truth = [{"instance_id": "a", "label": "attack", "scenario": "C2-A"}]
            run = EvaluationRun.create(Path(root), truth, {})
            run.save_corpus([{"instance_id": "a"}], {})
            for mode in ("baseline", "observe"):
                run.start_mode(mode)
                run.record_replay(mode, 1)
                run.complete_mode(mode, [{"instance_id": "a", "detected": None}], {})
            run.start_mode("action")
            run.record_replay("action", 1, mcp_journal_continuous=True)
            (run.path / "action-receipts.jsonl").write_text(
                json.dumps({"instance_id": "a", "status": "http_error", "http_status": 403}) + "\n", encoding="utf-8",
            )
            started_at = run.manifest()["modes"]["action"]["started_at"]
            (run.path / "action-gateway-detections.json").write_text(json.dumps({"start_time": started_at, "end_time": started_at, "items": [
                {"session_id": "a", "detection_id": "d1"},
            ]}), encoding="utf-8")
            (run.path / "action-detection-observations.json").write_text(json.dumps([
                {"instance_id": "a", "detected": True, "evidence_refs": ["detection:d1"], "detection_scope_complete": False},
            ]), encoding="utf-8")
            (run.path / "action-effect-observations.json").write_text(json.dumps([
                {"instance_id": "a", "effect": "unknown", "effect_evidence_ref": None},
            ]), encoding="utf-8")
            before = {service: {"boot_id": "boot-1", "high_water_seq": 0, "dropped": 0, "items": []} for service in SERVICES}
            after = {service: {"boot_id": "boot-1", "high_water_seq": 0, "dropped": 0, "items": []} for service in SERVICES}
            (run.path / "action-mcp-before.json").write_text(json.dumps(before), encoding="utf-8")
            (run.path / "action-mcp-after.json").write_text(json.dumps(after), encoding="utf-8")
            events = [
                {"id": 10, "session_id": "a", "event_source": "guardrail", "tool_name": "query",
                 "mcp_server": "mcp-customer-db", "attributes": {"phase": "pre", "inspection_status": "complete",
                 "action": "block", "inspection_mode": "action", "call_id": "c1", "proxy_kind": "mcp"}},
                {"id": 11, "session_id": "a", "event_source": "proxy", "outcome": "blocked",
                 "attributes": {"phase": "result", "operation_result": "rejected", "call_id": "c1"}},
            ]
            (run.path / "action-gateway-events.json").write_text(json.dumps({"start_time": started_at, "end_time": started_at, "items": events}), encoding="utf-8")
            (run.path / "action-enforcement-observations.json").write_text(
                json.dumps(enforcement_observations(truth, events)), encoding="utf-8",
            )
            result = finalize_mode(run.path, "action")
            self.assertEqual(result["counts"]["effective_blocks"], 1)
            self.assertEqual(result["metrics"]["effective_block_rate"], 1.0)
            observations = json.loads((run.path / "action-observations.json").read_text(encoding="utf-8"))
            self.assertEqual(observations[0]["effect"], "prevented")
            self.assertTrue(observations[0]["enforced_block"])


if __name__ == "__main__":
    unittest.main()
