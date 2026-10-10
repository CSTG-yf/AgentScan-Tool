import json
import tempfile
import unittest
from pathlib import Path

from integration.report import build_report, representative_chains, to_markdown
from dashboard.build_dashboard import build_data


class AgentRangeReportTest(unittest.TestCase):
    def test_scoped_report_uses_paired_run_and_retains_blocked_case(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            action = root / "bench" / "runs" / "paired" / "action"
            baseline = action.parent / "baseline"
            reports = root / "integration" / "reports"
            action.mkdir(parents=True)
            baseline.mkdir()
            reports.mkdir(parents=True)
            (action / "run.json").write_text(json.dumps({
                "mode": "action", "git_commit": "abc123", "arena_sha256": "arena-hash",
            }), encoding="utf-8")
            (baseline / "run.json").write_text('{"mode":"baseline"}', encoding="utf-8")
            (action / "summary.json").write_text(json.dumps({
                "overall": {"counts": {"tp": 1, "fp": 0}},
                "resources": {"baseline": {
                    "status": "complete", "manifest_compatibility": "verified",
                }},
            }), encoding="utf-8")
            (action / "runtime-events.jsonl").write_text(
                '{"instance_id":"attack","session_id":"attack","decision":"block"}\n',
                encoding="utf-8",
            )
            chains = [{"chain_id": f"chain:normal-{i}", "blocked": False,
                       "sequence_type": "normal", "nodes": []} for i in range(101)]
            chains.append({"chain_id": "chain:attack", "blocked": True,
                           "sequence_type": "attack", "block_node_id": "n1", "nodes": [
                               {"id": "n1", "raw_ref": "audit.db:42", "http_path": "/mcp",
                                "app_frames": [{"module": "app", "function": "run", "line": 7}],
                                "app_frames_source": "client_reported"},
                           ]})
            (action / "attack-chains.json").write_text(json.dumps({
                "event_count": 1, "chains": chains,
            }), encoding="utf-8")

            report = build_report(root, action.parent)
            self.assertEqual(report["runtime"]["attack_chain_count"], 102)
            self.assertTrue(report["chains"][0]["blocked"])
            self.assertEqual(report["benchmark"]["overall"]["counts"]["tp"], 1)
            self.assertTrue(report["benchmark_provenance"]["comparable_mode_set"])
            self.assertEqual(report["benchmark_provenance"]["action_run"],
                             "bench/runs/paired/action")
            self.assertFalse(any(path.startswith("bench/results/") for path in report["evidence_index"]))
            self.assertEqual(report["plan_traceability"]["scope"], "repository_path_existence_only")
            self.assertIn("audit.db:42", to_markdown(report))

            (action / "summary.json").write_text("{", encoding="utf-8")
            with self.assertRaises(json.JSONDecodeError):
                build_report(root, action.parent)

            (action / "summary.json").write_text("{}", encoding="utf-8")
            (action / "runtime-events.jsonl").write_text("{bad json}\n", encoding="utf-8")
            with self.assertRaises(json.JSONDecodeError):
                build_report(root, action.parent)

    def test_legacy_report_reads_existing_summary(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            reports = root / "integration" / "reports"
            results = root / "bench" / "results"
            reports.mkdir(parents=True)
            results.mkdir(parents=True)
            (results / "summary.json").write_text('{"legacy":true}', encoding="utf-8")
            report = build_report(root)
            self.assertTrue(report["benchmark"]["legacy"])
            self.assertEqual(report["runtime"]["event_count"], 0)

    def test_representative_chains_keep_one_block_per_type(self):
        chains = [
            {"blocked": True, "sequence_type": "a"},
            {"blocked": True, "sequence_type": "a"},
            {"blocked": True, "sequence_type": "b"},
            {"blocked": False, "sequence_type": "normal"},
        ]
        self.assertEqual(representative_chains(chains), [chains[0], chains[2], chains[3]])

    def test_dashboard_uses_scoped_action_metrics(self):
        data = build_data({
            "static": {
                "metrics": {"asset_found": 999, "required_risks_detected": 999},
                "evaluation": {"scope": "local_frozen_fixture",
                               "asset": {"tp": 27, "fn": 0}, "risk": {"tp": 13, "fn": 0}},
            },
            "benchmark_provenance": {"action_run": "bench/runs/paired/action"},
            "benchmark": {
                "overall": {
                    "counts": {"tp": 1, "fp": 0, "tn": 9, "fn": 0, "unknown": 0},
                    "metrics": {"recall": 1.0, "fpr": 0.0},
                    "normal_business": {"success_rate": 1.0},
                    "inspect_latency_ms": {"p95": 100},
                },
                "resources": {"cpu_increment_pct": 0.87, "baseline": {
                    "status": "complete", "manifest_compatibility": "verified",
                }},
            },
        })
        self.assertEqual(data["modes"]["action"]["counts"]["total"], 10)
        self.assertEqual(data["snapshot"][:2], [
            {"label": "资产识别", "value": "27/27"},
            {"label": "风险识别", "value": "13/13"},
        ])
        score = {row["name"]: row for row in data["scorecard"]}
        self.assertEqual(score["恶意实例 Recall"]["actual"], "100.0%")
        self.assertEqual(score["阻断响应 p95"]["actual"], "100ms")
        self.assertEqual(score["DefenseClaw 增量 CPU"]["status"], "pass")


if __name__ == "__main__":
    unittest.main()
