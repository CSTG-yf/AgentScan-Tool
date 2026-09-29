import json
import tempfile
import unittest
from pathlib import Path

from prepare import prepare_run


class PrepareTests(unittest.TestCase):
    def test_freezes_private_truth_and_public_corpus(self):
        with tempfile.TemporaryDirectory() as root:
            run = prepare_run(Path(root), seed=1337, total=28, malicious_target=7)
            truth = json.loads((run.path / "truth.json").read_text(encoding="utf-8"))
            public = json.loads((run.path / "public-corpus.json").read_text(encoding="utf-8"))
            trajectories = json.loads((run.path / "trajectories.json").read_text(encoding="utf-8"))
            self.assertEqual(len(truth), 28)
            self.assertEqual(len(public), 28)
            self.assertEqual({item["instance_id"] for item in truth}, {item["instance_id"] for item in public})
            self.assertEqual(sum(item["label"] == "attack" for item in truth), 7)
            self.assertTrue(trajectories)
            for item in public:
                self.assertTrue({"malicious", "kind", "evidence", "trajectory", "label"}.isdisjoint(item))

    def test_empty_filter_is_rejected(self):
        with tempfile.TemporaryDirectory() as root:
            with self.assertRaises(ValueError):
                prepare_run(Path(root), total=10, malicious_target=1, scenarios={"missing"})
            self.assertEqual(list(Path(root).iterdir()), [])


if __name__ == "__main__":
    unittest.main()
