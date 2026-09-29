import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scenario-runner"))
import runner


class FakeClient:
    def __init__(self, **_kwargs):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False


class ReplayReceiptTests(unittest.TestCase):
    def setUp(self):
        self.events = [{
            "instance_id": "B-RD-1", "t": 1, "scenario": "B-RD",
            "actor": {"sub": "rdev"}, "input": {"prompt": "review"},
        }]

    def test_receipt_contains_status_not_response_body(self):
        captured = []
        response = type("Response", (), {"status_code": 200, "text": "SECRET"})()
        with patch.object(runner.httpx, "Client", FakeClient), patch.object(runner, "fire_opspilot", return_value=response):
            result = runner.replay_events(self.events, receipt_sink=captured.append)
        self.assertEqual(result, captured)
        self.assertEqual(result[0]["instance_id"], "B-RD-1")
        self.assertEqual(result[0]["status"], "completed")
        self.assertEqual(result[0]["http_status"], 200)
        self.assertNotIn("SECRET", str(result))

    def test_failure_receipt_is_emitted_before_error(self):
        captured = []
        with patch.object(runner.httpx, "Client", FakeClient), patch.object(runner, "fire_opspilot", side_effect=RuntimeError("token=SECRET")):
            with self.assertRaises(RuntimeError):
                runner.replay_events(self.events, receipt_sink=captured.append)
        self.assertEqual(captured[0]["status"], "failed")
        self.assertEqual(captured[0]["error_type"], "RuntimeError")
        self.assertNotIn("SECRET", str(captured))


if __name__ == "__main__":
    unittest.main()
