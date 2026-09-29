import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from replay import replay_mode
from run_store import EvaluationRun


class FrozenReplayTests(unittest.TestCase):
    def make_run(self, root):
        run = EvaluationRun.create(Path(root), [{"instance_id": "a", "label": "attack"}], {})
        run.save_corpus([{"instance_id": "a", "t": 0, "input": {"prompt": "test"}}], {"a": []})
        return run

    def test_replay_keeps_mode_open_for_authoritative_evidence(self):
        with tempfile.TemporaryDirectory() as root:
            run = self.make_run(root)

            def fake_replay(_events, receipt_sink):
                receipt_sink({"instance_id": "a", "status": "completed", "http_status": 200, "elapsed_ms": 1})

            with patch("replay.inject_trajectories"), patch("replay.clear_trajectories"), patch("replay.replay_events", side_effect=fake_replay):
                self.assertEqual(replay_mode(run.path, "baseline"), 1)
            receipt = json.loads((run.path / "baseline-receipts.jsonl").read_text(encoding="utf-8"))
            self.assertEqual(receipt["instance_id"], "a")
            self.assertEqual(run.manifest()["modes"]["baseline"]["replay_status"], "completed")
            self.assertEqual(run.manifest()["modes"]["baseline"]["status"], "running")

    def test_hash_mismatch_never_starts_replay(self):
        with tempfile.TemporaryDirectory() as root:
            run = self.make_run(root)
            (run.path / "public-corpus.json").write_text("[]", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "hash mismatch"):
                replay_mode(run.path, "baseline")
            self.assertEqual(run.manifest()["status"], "prepared")


if __name__ == "__main__":
    unittest.main()
