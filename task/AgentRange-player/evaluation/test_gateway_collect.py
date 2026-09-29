import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from gateway_collect import collect_detections, detection_observations
from run_store import EvaluationRun


class FakeClient:
    def __init__(self, pages):
        self.pages = pages
        self.requests = []

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def get(self, url, params):
        self.requests.append((url, params))
        payload = self.pages[len(self.requests) - 1]
        response = Mock()
        response.json.return_value = payload
        return response


class GatewayCollectionTests(unittest.TestCase):
    def test_positive_detection_requires_matching_session_and_id(self):
        truth = [{"instance_id": "a"}, {"instance_id": "b"}]
        rows = detection_observations(truth, [
            {"session_id": "a", "detection_id": "d1"},
            {"session_id": "other", "detection_id": "d2"},
        ])
        self.assertEqual(rows[0]["detected"], True)
        self.assertEqual(rows[0]["evidence_refs"], ["detection:d1"])
        self.assertIsNone(rows[1]["detected"])
        self.assertFalse(rows[1]["detection_scope_complete"])

    def test_collects_real_pages_and_saves_evidence_without_token(self):
        with tempfile.TemporaryDirectory() as root:
            run = EvaluationRun.create(Path(root), [
                {"instance_id": "a", "label": "attack"},
                {"instance_id": "b", "label": "benign"},
            ], {})
            run.save_corpus([{"instance_id": "a"}, {"instance_id": "b"}], {})
            run.start_mode("baseline")
            run.record_replay("baseline", 2)
            client = FakeClient([{"total": 1, "items": [{"session_id": "a", "detection_id": "d1"}]}])
            with patch("gateway_collect.httpx.Client", return_value=client) as factory:
                rows = collect_detections(run.path, "baseline", token="SECRET")
            self.assertEqual(rows[0]["detected"], True)
            self.assertIsNone(rows[1]["detected"])
            factory.assert_called_once()
            self.assertEqual(factory.call_args.kwargs["headers"]["Authorization"], "Bearer SECRET")
            saved = (run.path / "baseline-gateway-detections.json").read_text(encoding="utf-8")
            self.assertNotIn("SECRET", saved)
            self.assertEqual(json.loads(saved)["count"], 1)

    def test_incomplete_pagination_fails_without_writing_observations(self):
        with tempfile.TemporaryDirectory() as root:
            run = EvaluationRun.create(Path(root), [{"instance_id": "a", "label": "attack"}], {})
            run.save_corpus([{"instance_id": "a"}], {})
            run.start_mode("baseline")
            run.record_replay("baseline", 1)
            client = FakeClient([{"total": 2, "items": [{"detection_id": "d1"}]}, {"total": 2, "items": []}])
            with patch("gateway_collect.httpx.Client", return_value=client):
                with self.assertRaisesRegex(ValueError, "pagination"):
                    collect_detections(run.path, "baseline", token="SECRET")
            self.assertFalse((run.path / "baseline-detection-observations.json").exists())


if __name__ == "__main__":
    unittest.main()
