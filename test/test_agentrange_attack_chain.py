import json
import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

from jsonschema import Draft202012Validator, ValidationError

from integration.attack_chain import build_chains, load_audit_events, load_run_scope

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
                                "app_frames": [{"module": "api.app", "function": "run_agent", "line": 42}],
                                "app_frames_source": "client_reported",
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
        self.assertEqual(chain["nodes"][0]["app_frames"][0]["function"], "run_agent")
        self.assertEqual(chain["nodes"][0]["app_frames_source"], "client_reported")
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

    def test_scoped_audit_excludes_old_runs_and_other_instances(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run_dir = root / "action"
            run_dir.mkdir()
            (run_dir / "run.json").write_text('{"mode":"action","total":1}', encoding="utf-8")
            (run_dir / "replay-process.json").write_text(json.dumps({
                "mode": "action", "returncode": 0,
                "started_at": "2026-09-29T00:00:00Z", "finished_at": "2026-09-29T00:00:10Z",
            }), encoding="utf-8")
            observations = run_dir / "observations.jsonl"
            observations.write_text('{"instance_id":"case-1","mode":"action"}\n', encoding="utf-8")
            audit_db = root / "audit.db"
            with closing(sqlite3.connect(audit_db)) as connection:
                connection.execute("""CREATE TABLE audit_events (
                    id INTEGER, timestamp TEXT, action TEXT, target TEXT, actor TEXT,
                    details TEXT, structured_json TEXT, severity TEXT, connector TEXT,
                    trace_id TEXT, session_id TEXT, destination_app TEXT, tool_name TEXT
                )""")
                for event_id, timestamp, instance_id in (
                    (1, "2026-09-28T23:59:59Z", "case-1"),
                    (2, "2026-09-29T00:00:05Z", "case-1"),
                    (3, "2026-09-29T00:00:05Z", "case-2"),
                    (4, "2026-09-29T00:00:16Z", "case-1"),
                ):
                    connection.execute("INSERT INTO audit_events VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)", (
                        event_id, timestamp, "agentrange-runtime-pre", "", "", "",
                        json.dumps({"instance_id": instance_id}), "INFO", "agentrange",
                        instance_id, instance_id, "", "",
                    ))
                connection.commit()
            window, ids = load_run_scope(run_dir)
            self.assertEqual([event["event_id"] for event in load_audit_events(
                audit_db, window=window, instance_ids=ids,
            )], [2])

            observations.write_text('{"instance_id":"case-1","mode":"baseline"}\n', encoding="utf-8")
            with self.assertRaises(ValueError):
                load_run_scope(run_dir)

    def test_block_node_prefers_decision_with_request_context(self):
        chain = build_chains([
            {"instance_id": "case-1", "stage": "pre", "decision": "block", "raw_ref": "audit.db:1"},
            {"instance_id": "case-1", "stage": "block", "decision": "block", "raw_ref": "audit.db:2",
             "http_path": "/mcp", "request_body": "blocked request"},
        ])[0]
        self.assertEqual(chain["block_node_id"], "n2")
        self.assertEqual(chain["nodes"][1]["request_excerpt"], "blocked request")


if __name__ == "__main__":
    unittest.main()
