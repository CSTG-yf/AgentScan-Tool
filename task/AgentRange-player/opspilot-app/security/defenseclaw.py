"""Small, optional client for DefenseClaw's synchronous inspect API.

The range remains runnable without DefenseClaw.  Setting
``DEFENSECLAW_API_BASE`` enables the integration; the gateway's own observe /
action mode remains the source of truth for whether a finding is enforced.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Any

import requests


class DefenseClawBlocked(RuntimeError):
    """Raised when the gateway returns an action-mode block decision."""

    def __init__(self, stage: str, verdict: dict[str, Any]):
        self.stage = stage
        self.verdict = verdict
        reason = verdict.get("reason") or "security policy"
        super().__init__(f"DefenseClaw blocked {stage}: {reason}")


@dataclass(frozen=True)
class DefenseClawClient:
    base_url: str
    token: str = ""
    timeout_seconds: float = 0.25
    fail_mode: str = "open"
    connector: str = "opspilot"

    @classmethod
    def from_env(cls) -> "DefenseClawClient":
        return cls(
            base_url=os.getenv("DEFENSECLAW_API_BASE", "").rstrip("/"),
            token=os.getenv("DEFENSECLAW_API_TOKEN", ""),
            timeout_seconds=float(os.getenv("DEFENSECLAW_TIMEOUT_SECONDS", "0.25")),
            fail_mode=os.getenv("DEFENSECLAW_FAIL_MODE", "open").strip().lower(),
            connector=os.getenv("DEFENSECLAW_CONNECTOR", "opspilot"),
        )

    @property
    def enabled(self) -> bool:
        return bool(self.base_url)

    def inspect_request(self, content: str, model: str, session_id: str) -> dict[str, Any]:
        return self._inspect(
            "request",
            "/api/v1/inspect/request",
            {"content": content, "model": model, "session_id": session_id},
        )

    def inspect_response(self, content: str, model: str, session_id: str) -> dict[str, Any]:
        return self._inspect(
            "response",
            "/api/v1/inspect/response",
            {"content": content, "model": model, "session_id": session_id},
        )

    def inspect_tool(
        self,
        tool: str,
        args: dict[str, Any],
        session_id: str,
        mcp_server: str,
        context: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        return self._inspect(
            "tool",
            "/api/v1/inspect/tool",
            {
                "tool": tool,
                "args": args,
                "direction": "tool_call",
                "session_id": session_id,
                "connector": self.connector,
                "mcp_server_name": mcp_server,
                "context": context or {},
            },
        )

    def inspect_tool_response(self, tool: str, output: Any, session_id: str) -> dict[str, Any]:
        return self._inspect(
            "tool-response",
            "/api/v1/inspect/tool-response",
            {"tool": tool, "output": output, "session_id": session_id},
        )

    def _inspect(self, stage: str, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        if not self.enabled:
            return {"action": "allow", "mode": "disabled", "severity": "NONE"}

        headers = {"Content-Type": "application/json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        try:
            response = requests.post(
                f"{self.base_url}{path}",
                headers=headers,
                data=json.dumps(payload, ensure_ascii=False),
                timeout=self.timeout_seconds,
            )
            response.raise_for_status()
            verdict = response.json()
        except (requests.RequestException, ValueError) as exc:
            if self.fail_mode == "closed":
                verdict = {
                    "action": "block",
                    "severity": "HIGH",
                    "reason": f"inspect service unavailable: {type(exc).__name__}",
                    "mode": "integration-fail-closed",
                }
            else:
                return {
                    "action": "allow",
                    "severity": "NONE",
                    "reason": f"inspect service unavailable: {type(exc).__name__}",
                    "mode": "integration-fail-open",
                }

        if verdict.get("action") == "block":
            raise DefenseClawBlocked(stage, verdict)
        return verdict


def session_id_from_headers(headers: dict[str, str] | None) -> str:
    if not headers:
        return "manual"
    return headers.get("X-Instance-Id") or headers.get("X-Trace-Id") or "manual"


def security_context_from_headers(headers: dict[str, str] | None) -> dict[str, Any]:
    if not headers:
        return {}
    try:
        scope = json.loads(headers.get("X-Acting-Scope", "{}"))
    except (TypeError, ValueError):
        scope = {}
    return {
        "principal": {
            "sub": headers.get("X-Acting-User", ""),
            "role": headers.get("X-Acting-Role", ""),
            "scope": scope if isinstance(scope, dict) else {},
        }
    }
