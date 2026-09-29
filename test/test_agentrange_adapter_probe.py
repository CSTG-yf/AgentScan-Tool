import tempfile
import unittest
from pathlib import Path

from cli.defenseclaw.agentrange_adapter import build_adapter_bundle


class AgentRangeAdapterProbeTest(unittest.TestCase):
    def test_generated_overlay_keeps_context_relay_and_mounts_probe(self):
        root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as directory:
            bundle = build_adapter_bundle(
                root / "task" / "AgentRange-player-full",
                output_dir=directory,
                mode="action",
                inspect_timeout_ms=1200,
            )
        compose = bundle.compose_text
        self.assertIn("/opt/defenseclaw/sitecustomize.py:ro", compose)
        self.assertIn("PYTHONPATH: /opt/defenseclaw", compose)
        self.assertIn("defenseclaw-context-relay:", compose)
        self.assertIn("DC_CONTEXT_RELAY_URL: http://defenseclaw-context-relay:9101", compose)
        self.assertIn("DC_INSPECT_TIMEOUT_MS: '1200'", compose)
        self.assertIn("DC_BYPASS_INSPECTION: ${DC_BYPASS_INSPECTION:-0}", compose)


if __name__ == "__main__":
    unittest.main()
