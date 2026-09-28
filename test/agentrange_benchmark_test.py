import json
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path

from bench.agentrange_benchmark import prepare_run, score_run
from bench.resource_sampler import docker_stats


class AgentRangeBenchmarkTest(unittest.TestCase):
    @patch("bench.resource_sampler.subprocess.run")
    def test_resource_sampler_parses_docker_stats(self, run):
        run.return_value.returncode = 0
        run.return_value.stdout = '{"Name":"mcp","CPUPerc":"1.25%","MemUsage":"2MiB / 4GiB","MemPerc":"0.05%"}\n'
        run.return_value.stderr = ""
        self.assertEqual(docker_stats(), [{"container": "mcp", "cpu_pct": 1.25, "memory_usage": "2MiB / 4GiB", "memory_pct": 0.05}])

    def test_prepare_separates_public_corpus_and_ground_truth(self):
        with tempfile.TemporaryDirectory() as directory:
            run_dir = Path(directory) / "run"
            manifest = prepare_run(run_dir, total=32, malicious_target=8)
            public_rows = [json.loads(line) for line in (run_dir / "public-corpus.jsonl").read_text(encoding="utf-8").splitlines()]
            ground_truth = [json.loads(line) for line in (run_dir / "gt.jsonl").read_text(encoding="utf-8").splitlines()]

            self.assertEqual(manifest["total"], 32)
            self.assertEqual(len(public_rows), len(ground_truth))
            self.assertTrue(all(not {"scenario", "kind", "malicious", "evidence", "trajectory"}.intersection(row) for row in public_rows))
            self.assertEqual({row["scenario_id"] for row in ground_truth if row["label"] == "benign"}, {"normal"})

    def test_score_requires_observation_and_calculates_confusion(self):
        with tempfile.TemporaryDirectory() as directory:
            run_dir = Path(directory) / "run"
            prepare_run(run_dir, total=16, malicious_target=4)
            truth = [json.loads(line) for line in (run_dir / "gt.jsonl").read_text(encoding="utf-8").splitlines()]
            observations = [
                {
                    "instance_id": row["instance_id"],
                    "decision": "block" if row["label"] == "malicious" else "allow",
                    "side_effect_reached": False,
                    "business_success": row["label"] == "benign",
                    "e2e_latency_ms": 12,
                }
                for row in truth
            ]
            (run_dir / "observations.jsonl").write_text("\n".join(json.dumps(row) for row in observations) + "\n", encoding="utf-8")
            report = score_run(run_dir)
            self.assertEqual(report["overall"]["counts"]["tp"], 4)
            self.assertEqual(report["overall"]["counts"]["tn"], 12)
            self.assertEqual(report["overall"]["counts"]["unknown"], 0)
            self.assertEqual(report["overall"]["metrics"]["recall"], 1.0)
            self.assertEqual(report["overall"]["normal_business"]["success_rate"], 1.0)


if __name__ == "__main__":
    unittest.main()
