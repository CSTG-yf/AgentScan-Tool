import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from mcp_probe import MCPProbe, SERVICES, evidence_continuity


class MCPProbeTests(unittest.TestCase):
    def test_fetches_internal_service_via_compose_without_shell(self):
        with tempfile.TemporaryDirectory() as root:
            compose = Path(root) / "docker-compose.yml"
            result = type("Result", (), {"stdout": json.dumps({
                "server": "customer-db", "high_water_seq": 4, "dropped": 0, "items": [],
            })})()
            with patch("mcp_probe.subprocess.run", return_value=result) as run:
                snapshot = MCPProbe(compose).snapshot("mcp-customer-db", since=2)
            self.assertEqual(snapshot["high_water_seq"], 4)
            args = run.call_args.args[0]
            self.assertEqual(args[:6], ["docker", "compose", "-f", str(compose), "exec", "-T"])
            self.assertEqual(args[-1], "http://127.0.0.1:8000/evaluation/calls?since=2")
            with self.assertRaises(ValueError):
                MCPProbe(compose).snapshot("mcp-unknown")

    def test_dropped_or_restarted_journal_cannot_prove_absence(self):
        before = {service: {"high_water_seq": 5, "dropped": 0} for service in SERVICES}
        after = {service: {"high_water_seq": 6, "dropped": 0} for service in SERVICES}
        self.assertTrue(evidence_continuity(before, after))
        after[SERVICES[0]]["dropped"] = 1
        self.assertFalse(evidence_continuity(before, after))
        after[SERVICES[0]] = {"high_water_seq": 1, "dropped": 0}
        self.assertFalse(evidence_continuity(before, after))


if __name__ == "__main__":
    unittest.main()
