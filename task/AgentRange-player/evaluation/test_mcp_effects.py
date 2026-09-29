import unittest
import sys
from pathlib import Path

from mcp_effects import observed_effects


class MCPEffectTests(unittest.TestCase):
    def test_c2d_trajectory_content_matches_managed_host_file(self):
        range_root = Path(__file__).resolve().parents[1]
        sys.path.insert(0, str(range_root / "attack"))
        from cat2.trajectories import C2D_ENV_LEAK_CONTENT

        self.assertEqual(
            C2D_ENV_LEAK_CONTENT,
            (range_root / "mcp" / "managed-host.env").read_text(encoding="utf-8"),
        )

    def test_only_positive_target_side_receipts_prove_occurrence(self):
        truth = [
            {"instance_id": "a", "scenario": "C2-A", "label": "attack"},
            {"instance_id": "b", "scenario": "C2-D", "label": "attack"},
            {"instance_id": "c", "scenario": "C2-A", "label": "attack"},
            {"instance_id": "d", "scenario": "C2-B", "label": "attack"},
        ]
        after = {
            "mcp-customer-db": {"items": [
                {"seq": 2, "instance_id": "a", "tool": "query", "facts": {"tenant": "globex", "returned_rows": 8}},
                {"seq": 3, "instance_id": "c", "tool": "query", "facts": {"tenant": "acme", "returned_rows": 8}},
            ]},
            "mcp-notes-sync": {"items": [
                {"seq": 5, "instance_id": "b", "tool": "sync_note", "facts": {"synced": True, "contains_env_markers": True, "content_sha256": "same"}},
            ]},
            "mcp-shell-runner": {"items": [
                {"seq": 4, "instance_id": "b", "tool": "read_file", "facts": {"path": "/app/.env", "chars": 50, "content_sha256": "same"}},
            ]},
        }
        rows = observed_effects(truth, after)
        self.assertEqual([row["effect"] for row in rows], ["occurred", "occurred", "unknown", "unknown"])
        self.assertEqual(rows[0]["effect_evidence_ref"], "mcp:mcp-customer-db:2")
        self.assertEqual(rows[1]["effect_evidence_ref"], "mcp:mcp-notes-sync:5")
        self.assertIsNone(rows[2]["effect_evidence_ref"])

    def test_static_note_without_matching_file_read_is_unverified(self):
        truth = [{"instance_id": "b", "scenario": "C2-D", "label": "attack"}]
        after = {
            "mcp-customer-db": {"items": []},
            "mcp-notes-sync": {"items": [{
                "seq": 5, "instance_id": "b", "tool": "sync_note",
                "facts": {"synced": True, "contains_env_markers": True, "content_sha256": "static"},
            }]},
            "mcp-shell-runner": {"items": [{
                "seq": 4, "instance_id": "b", "tool": "read_file",
                "facts": {"path": "/app/.env", "chars": 50, "content_sha256": "actual"},
            }]},
        }
        self.assertEqual(observed_effects(truth, after)[0]["effect"], "unknown")


if __name__ == "__main__":
    unittest.main()
