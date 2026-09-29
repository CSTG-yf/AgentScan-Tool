import csv
import json
import tempfile
import unittest
from pathlib import Path

from report import _csv_safe, build_report
from run_store import EvaluationRun


class ReportTests(unittest.TestCase):
    def test_csv_export_neutralizes_formula_cells(self):
        self.assertEqual(_csv_safe("=HYPERLINK(1)"), "'=HYPERLINK(1)")
        self.assertEqual(_csv_safe("  @SUM(1)"), "'  @SUM(1)")

    def test_completed_modes_generate_inspectable_report_without_fabricated_rates(self):
        with tempfile.TemporaryDirectory() as root:
            run = EvaluationRun.create(Path(root), [
                {"instance_id": "attack-1", "label": "attack", "scenario": "C2-D"},
                {"instance_id": "normal-1", "label": "benign", "scenario": "B-RD"},
            ], {"commit": "test"})
            with self.assertRaises(ValueError):
                build_report(run.path)
            for mode in ("baseline", "observe", "action"):
                run.start_mode(mode)
                run.complete_mode(mode, [
                    {"instance_id": "attack-1", "detected": None, "effect": "unknown"},
                    {"instance_id": "normal-1", "detected": False, "evidence_refs": [f"query:{mode}"],
                     "detection_scope_complete": True, "effect": "unknown"},
                ], {"source": "test"})
            report = build_report(run.path)
            self.assertEqual(report["modes"]["action"]["counts"]["TN"], 1)
            self.assertIsNone(report["modes"]["action"]["metrics"]["recall"])
            self.assertEqual(len(report["evidence_sha256"]["truth.json"]), 64)
            markdown = (run.path / "comparison-report.md").read_text(encoding="utf-8")
            self.assertIn("未验证", markdown)
            self.assertIn("truth.json", markdown)
            with (run.path / "comparison-instances.csv").open(encoding="utf-8", newline="") as file:
                rows = list(csv.DictReader(file))
            self.assertEqual(len(rows), 6)
            self.assertEqual(rows[0]["instance_id"], "attack-1")

    def test_tampered_mode_summary_is_rejected(self):
        with tempfile.TemporaryDirectory() as root:
            run = EvaluationRun.create(Path(root), [{"instance_id": "a", "label": "attack"}], {})
            for mode in ("baseline", "observe", "action"):
                run.start_mode(mode)
                run.complete_mode(mode, [{"instance_id": "a", "detected": None}], {})
            path = run.path / "action-report.json"
            report = json.loads(path.read_text(encoding="utf-8"))
            report["summary"]["counts"]["TP"] = 999
            path.write_text(json.dumps(report), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "does not match"):
                build_report(run.path)
            self.assertFalse((run.path / "comparison-report.md").exists())


if __name__ == "__main__":
    unittest.main()
