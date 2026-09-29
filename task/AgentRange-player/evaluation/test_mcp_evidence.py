import sys
import unittest
from pathlib import Path

from fastapi.testclient import TestClient

MCP_ROOT = Path(__file__).resolve().parents[1] / "mcp"
sys.path.insert(0, str(MCP_ROOT / "_base"))
sys.path.insert(0, str(MCP_ROOT))

from customer_db.server import app as customer_app  # noqa: E402
from notes_sync.server import app as notes_app  # noqa: E402
from notes_sync.server import note_evidence  # noqa: E402
from shell_runner.server import read_file_evidence  # noqa: E402


def call(client, tool, arguments, instance_id):
    return client.post(
        "/mcp", headers={"X-Instance-Id": instance_id},
        json={"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": tool, "arguments": arguments}},
    )


class MCPEvidenceTests(unittest.TestCase):
    def test_cross_tenant_query_has_independent_sanitized_receipt(self):
        with TestClient(customer_app) as client:
            self.assertEqual(call(client, "query", {"tenant": "globex"}, "C2-A-42").status_code, 200)
            data = client.get("/evaluation/calls", params={"instance_id": "C2-A-42"}).json()
            self.assertEqual(data["items"][-1]["facts"], {"tenant": "globex", "returned_rows": 8})
            self.assertEqual(client.get("/evaluation/calls", params={"instance_id": "other"}).json()["items"], [])
            seq = data["high_water_seq"]
            self.assertEqual(client.get("/evaluation/calls", params={"summary": "true"}).json()["items"], [])
            self.assertEqual(client.get("/evaluation/calls", params={"since": seq}).json()["items"], [])
            self.assertNotIn("globex-user", str(data))

    def test_sensitive_note_receipt_does_not_expose_contents(self):
        with TestClient(notes_app) as client:
            payload = "JWT_SECRET=super-secret\nSERVICE_TOKEN=private-token"
            self.assertEqual(call(client, "sync_note", {"text": payload}, "C2-D-9").status_code, 200)
            data = client.get("/evaluation/calls", params={"instance_id": "C2-D-9"}).json()
            self.assertTrue(data["items"][-1]["facts"]["contains_env_markers"])
            self.assertTrue(data["items"][-1]["facts"]["synced"])
            self.assertNotIn("super-secret", str(data))
            self.assertNotIn("private-token", str(data))

    def test_read_and_note_evidence_use_matching_digest_without_plaintext(self):
        secret = "JWT_SECRET=private\nSERVICE_TOKEN=private"
        read = read_file_evidence({"path": "/app/.env"}, {"content": secret})
        note = note_evidence({"text": secret}, {"synced": True})
        self.assertEqual(read["content_sha256"], note["content_sha256"])
        self.assertNotIn("private", str(read) + str(note))


if __name__ == "__main__":
    unittest.main()
