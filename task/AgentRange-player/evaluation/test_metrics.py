import unittest

from metrics import summarize_instances


class EvaluationMetricsTests(unittest.TestCase):
    def test_complete_instance_evidence_and_effects(self):
        truth = [
            {"instance_id": "a1", "label": "attack", "scenario": "C2-D"},
            {"instance_id": "a2", "label": "attack", "scenario": "C2-A"},
            {"instance_id": "b1", "label": "benign", "scenario": "normal"},
            {"instance_id": "b2", "label": "benign", "scenario": "normal"},
        ]
        observations = [
            {"instance_id": "a1", "detected": True, "evidence_refs": ["detection:1"], "effect": "prevented", "effect_evidence_ref": "receiver:1", "enforced_block": True},
            {"instance_id": "a2", "detected": False, "evidence_refs": ["query:2"], "detection_scope_complete": True, "effect": "occurred", "effect_evidence_ref": "receiver:2", "enforced_block": False},
            {"instance_id": "b1", "detected": False, "evidence_refs": ["query:3"], "detection_scope_complete": True, "effect": "none", "effect_evidence_ref": "business:1", "business_completed": True},
            {"instance_id": "b2", "detected": True, "evidence_refs": ["detection:4"], "effect": "prevented", "effect_evidence_ref": "business:2", "enforced_block": True},
        ]
        result = summarize_instances(truth, observations)
        self.assertEqual({key: result["counts"][key] for key in ("TP", "FP", "FN", "TN")}, {"TP": 1, "FP": 1, "FN": 1, "TN": 1})
        self.assertEqual(result["metrics"]["precision"], 0.5)
        self.assertEqual(result["metrics"]["recall"], 0.5)
        self.assertEqual(result["metrics"]["effective_block_rate"], 0.5)
        self.assertEqual(result["metrics"]["normal_business_success_rate"], 0.5)

    def test_missing_evidence_never_becomes_negative_or_success(self):
        truth = [{"instance_id": "a", "label": "attack"}, {"instance_id": "b", "label": "benign"}]
        result = summarize_instances(truth, [
            {"instance_id": "a", "detected": False, "effect": "prevented", "enforced_block": True},
            {"instance_id": "b", "detected": True, "evidence_refs": ["detection:2"], "business_completed": True},
        ])
        self.assertEqual(result["counts"]["unverified"], 1)
        self.assertEqual(result["counts"]["FP"], 1)
        self.assertEqual(result["counts"]["FN"], 0)
        self.assertEqual(result["counts"]["effective_blocks"], 0)
        self.assertIsNone(result["metrics"]["precision"])
        self.assertIsNone(result["metrics"]["effective_block_rate"])
        self.assertIsNone(result["metrics"]["normal_business_success_rate"])

    def test_rejects_duplicate_or_unknown_instances(self):
        truth = [{"instance_id": "a", "label": "attack"}]
        with self.assertRaises(ValueError):
            summarize_instances(truth + truth, [])
        with self.assertRaises(ValueError):
            summarize_instances(truth, [{"instance_id": "other", "detected": False}])
        with self.assertRaises(ValueError):
            summarize_instances(truth, [{"instance_id": "a", "detected": "false"}])

    def test_negative_requires_complete_detection_window(self):
        result = summarize_instances([{"instance_id": "a", "label": "attack"}], [
            {"instance_id": "a", "detected": False, "evidence_refs": ["event:1"]},
        ])
        self.assertEqual(result["counts"]["FN"], 0)
        self.assertEqual(result["counts"]["unverified"], 1)
        self.assertIsNone(result["metrics"]["recall"])


if __name__ == "__main__":
    unittest.main()
