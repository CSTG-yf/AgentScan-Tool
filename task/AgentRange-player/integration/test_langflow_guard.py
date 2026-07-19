import asyncio
import json

import langflow_guard


class FakeURL:
    path = "/api/v1/validate/code"
    query = ""


class FakeRequest:
    method = "POST"
    url = FakeURL()
    headers = {"x-instance-id": "instance-c1", "x-trace-id": "trace-c1"}


def test_disabled_ingress_is_noop(monkeypatch):
    monkeypatch.setattr(langflow_guard, "DEFENSECLAW_API_BASE", "")
    verdict = asyncio.run(langflow_guard.inspect_ingress(FakeRequest(), b"{}"))
    assert verdict == {"action": "allow", "mode": "disabled"}


def test_unavailable_ingress_honors_closed_mode(monkeypatch):
    class BrokenClient:
        def __init__(self, *args, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return False

        async def post(self, *args, **kwargs):
            raise langflow_guard.httpx.ConnectError("offline")

    monkeypatch.setattr(langflow_guard, "DEFENSECLAW_API_BASE", "http://gateway")
    monkeypatch.setattr(langflow_guard, "FAIL_MODE", "closed")
    monkeypatch.setattr(langflow_guard.httpx, "AsyncClient", BrokenClient)
    verdict = asyncio.run(langflow_guard.inspect_ingress(FakeRequest(), b"payload"))
    assert verdict["action"] == "block"
    assert verdict["mode"] == "integration-fail-closed"
    assert verdict["latency_ms"] >= 0


def test_langflow_evidence_redacts_credentials():
    redacted = langflow_guard.redact_evidence(
        {"content_type": "application/json", "body": "token=abc123", "password": "hunter2"}
    )
    rendered = json.dumps(redacted)
    assert "abc123" not in rendered
    assert "hunter2" not in rendered
