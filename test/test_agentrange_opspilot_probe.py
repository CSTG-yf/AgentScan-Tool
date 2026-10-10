import base64
import importlib.util
import json
import os
import unittest
from pathlib import Path
from unittest.mock import patch

import requests

PROBE_PATH = Path(__file__).resolve().parents[1] / "task" / "agentrange-adapter" / "opspilot_probe.py"
SPEC = importlib.util.spec_from_file_location("opspilot_probe", PROBE_PATH)
probe = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(probe)


def synthetic_call(session, url, headers=None):
    namespace = {"session": session, "url": url, "headers": headers}
    source = "def run_stub_agent():\n    return session.request('POST', url, headers=headers)\n"
    exec(compile(source, "/app/api/app.py", "exec"), namespace)
    return namespace["run_stub_agent"]()


class OpsPilotProbeTest(unittest.TestCase):
    def setUp(self):
        self.calls = []

        def capture(_session, method, url, **kwargs):
            self.calls.append((method, url, kwargs))
            return object()

        self.request_patch = patch.object(requests.sessions.Session, "request", capture)
        self.request_patch.start()
        self.env_patch = patch.dict(os.environ, {
            "LLM_BASE": "http://defenseclaw-llm-proxy:8000/v1",
            "LANGFLOW_BASE": "http://defenseclaw-langflow-ingress:7860",
            "MCP_CUSTOMER_DB": "http://defenseclaw-mcp-proxy:8000/mcp-customer-db/mcp",
        }, clear=True)
        self.env_patch.start()
        self.addCleanup(self.env_patch.stop)
        self.addCleanup(self.request_patch.stop)
        self.addCleanup(probe.uninstall)

    def test_real_app_frame_is_bounded_and_caller_headers_are_unchanged(self):
        self.assertTrue(probe.install())
        self.assertFalse(probe.install())
        headers = {"Authorization": "Bearer secret", "X-Instance-Id": "instance-1"}
        synthetic_call(requests.Session(), "http://defenseclaw-llm-proxy:8000/v1/chat/completions", headers)

        sent = self.calls[0][2]["headers"]
        self.assertEqual(headers, {"Authorization": "Bearer secret", "X-Instance-Id": "instance-1"})
        self.assertIsNot(sent, headers)
        encoded = sent[probe.FRAME_HEADER]
        self.assertLessEqual(len(encoded.encode("ascii")), probe.MAX_HEADER_BYTES)
        frames = json.loads(base64.urlsafe_b64decode(encoded))
        self.assertEqual(frames, [{"module": "api.app", "function": "run_stub_agent", "line": 2}])
        self.assertNotIn("secret", encoded)
        self.assertNotIn("Authorization", str(frames))

    def test_non_targets_are_untouched_and_internal_header_cannot_be_spoofed(self):
        probe.install()
        headers = {"X-DefenseClaw-App-Frames": "forged", "Authorization": "Bearer secret"}
        session = requests.Session()
        synthetic_call(session, "https://example.com/v1/chat/completions", headers)
        self.assertIs(self.calls[-1][2]["headers"], headers)
        synthetic_call(session, "http://defenseclaw-llm-proxy:8000/v1-other", headers)
        self.assertIs(self.calls[-1][2]["headers"], headers)
        synthetic_call(session, "http://defenseclaw-mcp-proxy:8000/mcp-customer-db/mcp", headers)
        self.assertNotEqual(self.calls[-1][2]["headers"][probe.FRAME_HEADER], "forged")
        self.assertEqual(headers["X-DefenseClaw-App-Frames"], "forged")

    def test_langflow_ingress_receives_frames_without_matching_external_or_other_ports(self):
        probe.install()
        session = requests.Session()
        headers = {"X-Instance-Id": "instance-2"}
        synthetic_call(session, "http://defenseclaw-langflow-ingress:7860/api/v1/run/flow-1", headers)
        sent = self.calls[-1][2]["headers"]
        frames = json.loads(base64.urlsafe_b64decode(sent[probe.FRAME_HEADER]))
        self.assertEqual(frames[0]["function"], "run_stub_agent")
        self.assertEqual(headers, {"X-Instance-Id": "instance-2"})

        for url in (
            "http://defenseclaw-langflow-ingress:7861/api/v1/run/flow-1",
            "http://defenseclaw-langflow-ingress.example.com:7860/api/v1/run/flow-1",
            "https://example.com/api/v1/run/flow-1",
        ):
            synthetic_call(session, url, headers)
            self.assertIs(self.calls[-1][2]["headers"], headers)

    def test_deep_stack_respects_frame_count_and_header_byte_cap(self):
        probe.install()
        namespace = {"session": requests.Session()}
        source = (
            "def recurse(depth):\n"
            "    if depth: return recurse(depth - 1)\n"
            "    return session.request('GET', 'http://defenseclaw-llm-proxy:8000/v1/chat/completions')\n"
        )
        exec(compile(source, "/app/skills/loader.py", "exec"), namespace)
        namespace["recurse"](30)
        encoded = self.calls[-1][2]["headers"][probe.FRAME_HEADER]
        frames = json.loads(base64.urlsafe_b64decode(encoded))
        self.assertLessEqual(len(frames), probe.MAX_FRAMES)
        self.assertLessEqual(len(encoded.encode("ascii")), probe.MAX_HEADER_BYTES)
        self.assertTrue(all(frame["module"] == "skills.loader" for frame in frames))

        with patch.object(probe, "MAX_HEADER_BYTES", 200):
            namespace["recurse"](30)
            capped = self.calls[-1][2]["headers"][probe.FRAME_HEADER]
            capped_frames = json.loads(base64.urlsafe_b64decode(capped))
            self.assertLess(len(capped_frames), probe.MAX_FRAMES)
            self.assertLessEqual(len(capped.encode("ascii")), 200)

    def test_sitecustomize_installs_probe_on_import(self):
        original = requests.sessions.Session.request
        site_spec = importlib.util.spec_from_file_location("sitecustomize", PROBE_PATH)
        site_module = importlib.util.module_from_spec(site_spec)
        try:
            site_spec.loader.exec_module(site_module)
            self.assertIsNot(requests.sessions.Session.request, original)
        finally:
            site_module.uninstall()
        self.assertIs(requests.sessions.Session.request, original)


if __name__ == "__main__":
    unittest.main()
