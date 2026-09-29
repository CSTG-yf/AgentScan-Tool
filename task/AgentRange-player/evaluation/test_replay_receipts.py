import sys
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

import httpx

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

    def test_http_block_is_recorded_and_next_instance_replays(self):
        events = self.events + [{**self.events[0], "instance_id": "B-RD-2", "t": 2}]
        blocked_response = httpx.Response(403, request=httpx.Request("POST", "http://localhost/run"))
        error = httpx.HTTPStatusError("blocked", request=blocked_response.request, response=blocked_response)
        ok_response = type("Response", (), {"status_code": 200})()
        captured = []
        with patch.object(runner.httpx, "Client", FakeClient), patch.object(
            runner, "fire_opspilot", side_effect=[error, ok_response],
        ):
            runner.replay_events(events, receipt_sink=captured.append, continue_on_http_error=True)
        self.assertEqual([item["status"] for item in captured], ["http_error", "completed"])
        self.assertEqual(captured[0]["http_status"], 403)

    def test_login_token_is_actually_reused(self):
        action = runner.plan_actions(self.events)[0]
        response = httpx.Response(200, request=httpx.Request("POST", "http://localhost/run"))
        client = Mock()
        client.post.return_value = response
        tokens = {}
        with patch.object(runner, "login_token", return_value="cached") as login:
            runner.fire_opspilot(client, action, tokens)
            runner.fire_opspilot(client, action, tokens)
        login.assert_called_once()


if __name__ == "__main__":
    unittest.main()
