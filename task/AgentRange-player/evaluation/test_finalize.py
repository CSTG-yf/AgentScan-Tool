import json
import tempfile
import unittest
from pathlib import Path

from finalize import finalize_mode
from run_store import EvaluationRun


class FinalizeTests(unittest.TestCase):
    def make_run(self, root):
        run = EvaluationRun.create(Path(root), [
            {"instance_id": "a", "label": "attack", "scenario": "C2-A"},
            {"instance_id": "b", "label": "benign", "scenario": "B-RD"},
        ], {})
        run.save_corpus([{"instance_id": "a"}, {"instance_id": "b"}], {})
        run.start_mode("baseline")
        run.record_replay("baseline", 2)
        (run.path / "baseline-receipts.jsonl").write_text(
            json.dumps({"instance_id": "a", "status": "http_error", "http_status": 403}) + "\n" +
            json.dumps({"instance_id": "b", "status": "completed", "http_status": 200}) + "\n",
            encoding="utf-8",
        )
        (run.path / "baseline-detection-observations.json").write_text(json.dumps([
            {"instance_id": "a", "detected": True, "evidence_refs": ["detection:d1"], "detection_scope_complete": False},
            {"instance_id": "b", "detected": None, "evidence_refs": [], "detection_scope_complete": False},
        ]), encoding="utf-8")
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


if __name__ == "__main__":
    unittest.main()
