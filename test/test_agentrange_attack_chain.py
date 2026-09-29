import json
import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

from jsonschema import Draft202012Validator, ValidationError

from integration.attack_chain import build_chains, load_audit_events

SCHEMA = json.loads(
    (Path(__file__).resolve().parents[1] / "integration" / "agentrange_contracts" / "attack-chain.schema.json")
    .read_text(encoding="utf-8")
)


class AgentRangeAttackChainTest(unittest.TestCase):
    def test_audit_rows_produce_schema_valid_chain_with_truthful_evidence_levels(self):
        with tempfile.TemporaryDirectory() as directory:
            audit_db = Path(directory) / "audit.db"
            with closing(sqlite3.connect(audit_db)) as connection:
                connection.execute(
                    """CREATE TABLE audit_events (
                        id INTEGER, timestamp TEXT, action TEXT, target TEXT, actor TEXT,
                        details TEXT, structured_json TEXT, severity TEXT, connector TEXT,
                        trace_id TEXT, session_id TEXT, destination_app TEXT, tool_name TEXT
                    )"""
                )
                for event_id, stage, decision in ((1, "pre", "allow"), (2, "block", "block")):
                    connection.execute(
                        "INSERT INTO audit_events VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        (
                            event_id, f"2026-09-29T00:00:0{event_id}Z", f"agentrange-runtime-{stage}",
                            "mcp", "defenseclaw-agentrange-sidecar", "", json.dumps({
                                "instance_id": "instance-1", "session_id": "session-1", "trace_id": "trace-1",
                                "stage": stage, "decision": decision, "tool_name": "shell_runner_run",
                            }),
                            "HIGH", "agentrange", "trace-1", "session-1", "opspilot-app", "shell_runner_run",
                        ),
                    )
                connection.commit()
            chains = build_chains(load_audit_events(audit_db))

        self.assertEqual(len(chains), 1)
        chain = chains[0]
        Draft202012Validator(SCHEMA).validate(chain)
        self.assertEqual(chain["instance_id"], "instance-1")
        self.assertEqual(chain["session_id"], "session-1")
        self.assertEqual([node["evidence_level"] for node in chain["nodes"]], ["direct", "direct"])
        self.assertEqual([node["raw_ref"] for node in chain["nodes"]], ["audit.db:1", "audit.db:2"])
        self.assertEqual(chain["edges"][0]["evidence_level"], "time_window_inference")
        self.assertTrue(chain["blocked"])

        del chain["edges"][0]["evidence_level"]
        with self.assertRaises(ValidationError):
            Draft202012Validator(SCHEMA).validate(chain)

    def test_missing_raw_reference_is_not_claimed_as_direct_evidence(self):
        chain = build_chains([{"instance_id": "instance-2", "session_id": "session-2", "stage": "pre"}])[0]
        Draft202012Validator(SCHEMA).validate(chain)
        self.assertEqual(chain["nodes"][0]["evidence_level"], "time_window_inference")
        self.assertEqual(chain["nodes"][0]["raw_ref"], "")


if __name__ == "__main__":
    unittest.main()
