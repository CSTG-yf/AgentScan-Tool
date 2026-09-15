"""AgentRange runtime delivery tests: no Docker, network or real audit DB."""
import importlib.util
import io
import json
import os
from pathlib import Path
import unittest
from unittest.mock import patch
from uuid import uuid4

spec = importlib.util.spec_from_file_location(
    "agentrange_runtime_sidecar",
    Path(__file__).resolve().parents[1] / "cli/defenseclaw/agentrange_sidecar.py",
)
sidecar = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sidecar)


class Response:
    def __init__(self, data, headers=None):
        self.data = json.dumps(data).encode()
        self.headers = headers or {}

    def __enter__(self): return self
    def __exit__(self, *args): return False
    def read(self): return self.data


class AgentRangeRuntimeTests(unittest.TestCase):
    def state(self):
        return {
            "context": {"connector": "agentrange", "session_id": "session-1",
                        "trace_id": "trace-1", "call_id": str(uuid4()),
                        "event_id": str(uuid4()), "phase": "pre",
                        "proxy_kind": "langflow", "operation": "code.validate",
                        "http_method": "POST", "http_path": "/api/v1/validate/code",
                        "target": "langflow"},
            "result_id": str(uuid4()), "inspection_ids": [], "pending_checks": [],
        }

    def test_inspection_payload_and_independent_result_retry(self):
        state = self.state()
        token = sidecar._runtime_request.set(state)
        calls = []

        def urlopen(request, **kwargs):
            calls.append((request.full_url, json.loads(request.data)))
            if request.full_url.endswith('/api/v1/runtime-results') and sum(
                    url.endswith('/api/v1/runtime-results') for url, _ in calls) == 1:
                raise OSError('temporary delivery failure')
            return Response({'action': 'allow', 'mode': 'observe'},
                            {'X-DefenseClaw-Runtime-Status': 'recorded'})

        try:
            with patch.object(sidecar, 'urlopen', side_effect=urlopen), patch.dict(
                    os.environ, {'DEFENSECLAW_GATEWAY_TOKEN': 'test-token'}):
                verdict, error = sidecar.inspect_request('safe content', 'session-1')
                self.assertIsNone(error)
                sidecar.emit_runtime_result('response_received', 200)
            context = calls[0][1]['runtime_context']
            self.assertEqual(context['call_id'], state['context']['call_id'])
            self.assertEqual(context['session_id'], 'session-1')
            results = [body for url, body in calls if url.endswith('/api/v1/runtime-results')]
            self.assertEqual(len(results), 2)
            self.assertEqual(results[0], results[1])
            self.assertEqual(results[0]['inspection_event_ids'], [context['event_id']])
            self.assertEqual(results[0]['outcome'], 'response_received')
            self.assertNotIn('content', results[0])
        finally:
            sidecar._runtime_request.reset(token)

    def test_failed_check_persistence_retries_original_identity(self):
        state = self.state()
        token = sidecar._runtime_request.set(state)
        calls = []

        def urlopen(request, **kwargs):
            calls.append((request.full_url, json.loads(request.data)))
            status = 'failed' if len(calls) == 1 else 'recorded'
            return Response({'action': 'allow'}, {'X-DefenseClaw-Runtime-Status': status})

        try:
            with patch.object(sidecar, 'urlopen', side_effect=urlopen):
                sidecar.inspect_request('safe content', 'session-1')
                sidecar.emit_runtime_result('forward_failed', 502)
            checks = [body for url, body in calls if url.endswith('/api/v1/inspect/request')]
            self.assertEqual(len(checks), 2)
            self.assertEqual(checks[0], checks[1])
            self.assertEqual(len(state['inspection_ids']), 1)
            self.assertEqual(state['pending_checks'], [])
        finally:
            sidecar._runtime_request.reset(token)

    def test_legacy_calls_and_forwarding_identity(self):
        token = sidecar._runtime_request.set(None)
        captured = []
        try:
            with patch.object(sidecar, 'urlopen', side_effect=lambda req, **kw:
                              captured.append(req) or Response({'action': 'allow'})):
                sidecar.inspect_request('safe', 'legacy-session')
            self.assertNotIn('runtime_context', json.loads(captured[0].data))
            state = self.state()
            sidecar._runtime_request.set(state)
            handler = object.__new__(sidecar.AgentRangeProxyHandler)
            handler.command = 'POST'
            handler.headers = {}
            handler._trace_id = 'trace-1'
            response = Response({})
            response.status = 200
            response.headers = {}
            with patch.object(sidecar, 'urlopen', side_effect=lambda req, **kw:
                              captured.append(req) or response):
                handler._forward('http://service/endpoint', b'{}')
            req = captured[-1]
            self.assertEqual(req.get_header('X-instance-id'), 'session-1')
            self.assertEqual(req.get_header('X-defenseclaw-session-id'), 'session-1')
            self.assertEqual(req.get_header('X-defenseclaw-trace-id'), 'trace-1')
        finally:
            sidecar._runtime_request.reset(token)


if __name__ == '__main__':
    unittest.main()
