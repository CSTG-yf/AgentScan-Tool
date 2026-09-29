"""AgentRange runtime delivery tests: no Docker, network or real audit DB."""
import importlib.util
import io
import json
import os
import base64
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
    def test_auth_token_response_is_redacted_for_inspection(self):
        token = "eyJ" + "a" * 20 + ".eyJ" + "b" * 20 + ".signature"
        original = json.dumps({"access_token": token, "token_type": "bearer", "message": "normal"}).encode()
        inspected = sidecar.inspection_response_body(
            "langflow", "/api/v1/auto_login", 200, original
        )
        self.assertNotIn(token.encode(), inspected)
        self.assertEqual(json.loads(inspected)["access_token"], "[issued credential]")
        self.assertEqual(json.loads(inspected)["message"], "normal")
        self.assertEqual(
            sidecar.inspection_response_body("langflow", "/api/v1/validate/code", 200, original),
            original,
        )

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
                sidecar.emit_runtime_result('response_received', 200).result(timeout=2)
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
                sidecar.emit_runtime_result('forward_failed', 502).result(timeout=2)
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

    def test_authorization_context_is_normalized_from_adapter_headers(self):
        headers = {
            'X-Acting-User': 'lwang',
            'X-Acting-Role': 'support-agent',
            'X-Acting-Scope': json.dumps({'tenant': 'acme'}),
        }
        self.assertEqual(
            sidecar.extract_authorization_context(headers),
            {'principal': {
                'sub': 'lwang',
                'role': 'support-agent',
                'scope': {'tenant': 'acme'},
            }},
        )

    def test_tool_inspection_carries_authorization_context(self):
        state = self.state()
        state['authorization_context'] = {
            'principal': {'sub': 'lwang', 'scope': {'tenant': 'acme'}},
        }
        token = sidecar._runtime_request.set(state)
        captured = []
        try:
            with patch.object(sidecar, 'urlopen', side_effect=lambda req, **kw:
                              captured.append(json.loads(req.data)) or Response({'action': 'allow'})):
                verdict, error = sidecar.inspect_tool(
                    'customer_db_query', {'tenant': 'globex'}, 'session-1',
                    mcp_server='customer-db',
                )
            self.assertIsNone(error)
            self.assertEqual(verdict['action'], 'allow')
            self.assertEqual(captured[0]['context'], state['authorization_context'])
            self.assertEqual(captured[0]['mcp_server_name'], 'customer-db')
        finally:
            sidecar._runtime_request.reset(token)

    def test_jwt_claims_are_normalized_for_downstream_context(self):
        def segment(value):
            return base64.urlsafe_b64encode(json.dumps(value, separators=(",", ":")).encode()).decode().rstrip("=")

        token = ".".join([
            segment({"alg": "HS256"}),
            segment({"sub": "lwang", "role": "support-agent", "scope": {"tenant": "acme"}}),
            "signature",
        ])
        self.assertEqual(
            sidecar.extract_jwt_authorization_context({"Authorization": f"Bearer {token}"}),
            {"principal": {"sub": "lwang", "role": "support-agent", "scope": {"tenant": "acme"}}},
        )

    def test_context_relay_registers_and_retrieves_by_session_and_trace(self):
        calls = []

        def urlopen(request, **kwargs):
            calls.append((request.get_method(), request.full_url, json.loads(request.data) if request.data else None))
            if request.get_method() == "GET":
                return Response({"context": {"principal": {"scope": {"tenant": "acme"}}}})
            return Response({})

        with patch.object(sidecar, "urlopen", side_effect=urlopen), patch.dict(
                os.environ, {"DC_CONTEXT_RELAY_URL": "http://relay:9101"}):
            context = {"principal": {"scope": {"tenant": "acme"}}}
            self.assertEqual(sidecar.relay_authorization_context("s-1", "t-1", context), context)
            self.assertEqual(sidecar.relay_authorization_context("s-1", "t-1", None), {"principal": {"scope": {"tenant": "acme"}}})
        self.assertEqual([item[0] for item in calls], ["PUT", "GET"])
        self.assertIn("session_id=s-1", calls[1][1])
        self.assertIn("trace_id=", calls[1][1])


if __name__ == '__main__':
    unittest.main()
