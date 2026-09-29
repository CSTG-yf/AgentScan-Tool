import json
import tempfile
import unittest
from pathlib import Path

from run_store import EvaluationRun


class EvaluationRunTests(unittest.TestCase):
    def test_modes_are_durable_ordered_and_non_overwriting(self):
        with tempfile.TemporaryDirectory() as root:
            truth = [{"instance_id": "attack-1", "label": "attack", "scenario": "C2-D"}]
            run = EvaluationRun.create(Path(root), truth, {"commit": "abc", "seed": 1337})
            other = EvaluationRun.create(Path(root), truth, {"commit": "abc", "seed": 1337})
            self.assertNotEqual(run.path, other.path)
            with self.assertRaises(ValueError):
                run.start_mode("action")
            for mode in ("baseline", "observe", "action"):
                run.start_mode(mode)
                report = run.complete_mode(mode, [
                    {"instance_id": "attack-1", "detected": True, "evidence_refs": [f"detection:{mode}"], "effect": "unknown"},
                ], {"config_hash": "sha256:test"})
                self.assertEqual(report["counts"]["TP"], 1)
                self.assertIsNone(report["metrics"]["effective_block_rate"])
                self.assertTrue((run.path / f"{mode}-report.json").is_file())
            self.assertEqual(run.manifest()["status"], "completed")
            self.assertEqual(json.loads((run.path / "truth.json").read_text())[0]["label"], "attack")
            with self.assertRaises(ValueError):
                run.start_mode("baseline")

    def test_failure_preserves_prior_mode_and_truth(self):
        with tempfile.TemporaryDirectory() as root:
            run = EvaluationRun.create(Path(root), [{"instance_id": "a", "label": "attack"}], {})
            run.start_mode("baseline")
            run.complete_mode("baseline", [{"instance_id": "a", "detected": None}], {"log": "baseline.log"})
            run.start_mode("observe")
            run.interrupt("observe", "docker unavailable")
            self.assertEqual(run.manifest()["status"], "failed")
            self.assertTrue((run.path / "baseline-report.json").is_file())
            self.assertTrue((run.path / "truth.json").is_file())
            with self.assertRaises(ValueError):
                run.start_mode("action")

    def test_incomplete_mode_cannot_be_marked_complete(self):
        with tempfile.TemporaryDirectory() as root:
            with self.assertRaises(ValueError):
                EvaluationRun.create(Path(root), [], {})
            run = EvaluationRun.create(Path(root), [{"instance_id": "a", "label": "attack"}], {})
            run.start_mode("baseline")
            with self.assertRaises(ValueError):
                run.complete_mode("baseline", [], {})
            self.assertEqual(run.manifest()["modes"]["baseline"]["status"], "running")

    def test_frozen_corpus_rejects_truth_leak_and_overwrite(self):
        with tempfile.TemporaryDirectory() as root:
            run = EvaluationRun.create(Path(root), [{"instance_id": "a", "label": "attack"}], {})
            with self.assertRaises(ValueError):
                run.save_corpus([{"instance_id": "a", "evidence": {"outcome": "exfiltration"}}], {})
            self.assertNotIn("corpus", run.manifest())
            run.save_corpus([{"instance_id": "a", "input": {"prompt": "test"}}], {"a": []})
            manifest = run.manifest()
            self.assertEqual(manifest["corpus"]["instances"], 1)
            self.assertEqual(len(manifest["corpus"]["public_sha256"]), 64)
            with self.assertRaises(ValueError):
                run.save_corpus([{"instance_id": "a"}], {})


if __name__ == "__main__":
    unittest.main()
