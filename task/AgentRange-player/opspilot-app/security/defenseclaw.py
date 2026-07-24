"""Small, optional client for DefenseClaw's synchronous inspect API.

The range remains runnable without DefenseClaw.  Setting
``DEFENSECLAW_API_BASE`` enables the integration; the gateway's own observe /
action mode remains the source of truth for whether a finding is enforced.
"""

from __future__ import annotations

import json
import os
import re
import threading
import time
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import requests


_EVIDENCE_LOCK = threading.Lock()
_SENSITIVE_KEY = re.compile(r"(?:authorization|cookie|token|password|passwd|secret|api[_-]?key)", re.IGNORECASE)
_SENSITIVE_VALUE = re.compile(
    r"(?i)((?:authorization\s*:\s*bearer|api[_-]?key|token|password|passwd|secret)\s*[:=]\s*)[^\s,;&]+"
)


def redact_evidence(value: Any, max_string_chars: int = 16_384) -> Any:
    """Remove credentials from evidence while retaining behavioral indicators."""
    if isinstance(value, dict):
        return {
            str(key): "[REDACTED]" if _SENSITIVE_KEY.search(str(key)) else redact_evidence(item, max_string_chars)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [redact_evidence(item, max_string_chars) for item in value]
    if isinstance(value, str):
        cleaned = _SENSITIVE_VALUE.sub(r"\1[REDACTED]", value)
        if len(cleaned) > max_string_chars:
            return cleaned[:max_string_chars] + "...[TRUNCATED]"
        return cleaned
    return value


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
    evidence_path: str = ""

    @classmethod
    def from_env(cls) -> "DefenseClawClient":
        return cls(
            base_url=os.getenv("DEFENSECLAW_API_BASE", "").rstrip("/"),
            token=os.getenv("DEFENSECLAW_API_TOKEN", ""),
            timeout_seconds=float(os.getenv("DEFENSECLAW_TIMEOUT_SECONDS", "0.25")),
            fail_mode=os.getenv("DEFENSECLAW_FAIL_MODE", "open").strip().lower(),
            connector=os.getenv("DEFENSECLAW_CONNECTOR", "opspilot"),
            evidence_path=os.getenv("RANGE_EVIDENCE_PATH", ""),
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

        started = time.perf_counter()
        headers = {"Content-Type": "application/json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        headers["X-DefenseClaw-Client"] = self.connector
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
                verdict = {
                    "action": "allow",
                    "severity": "NONE",
                    "reason": f"inspect service unavailable: {type(exc).__name__}",
                    "mode": "integration-fail-open",
                }

        latency_ms = round((time.perf_counter() - started) * 1000, 3)
        verdict = dict(verdict)
        verdict.setdefault("mode", "gateway")
        verdict.setdefault("severity", "NONE")
        verdict["latency_ms"] = latency_ms
        self._write_evidence(stage, payload, verdict)

        if verdict.get("action") == "block":
            raise DefenseClawBlocked(stage, verdict)
        return verdict

    def _write_evidence(self, stage: str, payload: dict[str, Any], verdict: dict[str, Any]) -> None:
        if not self.evidence_path:
            return
        event_id = str(uuid.uuid4())
        session_id = str(payload.get("session_id") or "manual")
        mcp_server = str(payload.get("mcp_server_name") or "")
        tool = str(payload.get("tool") or "")
        stage_map = {
            "request": "prompt",
            "response": "final_response",
            "tool": "mcp_call",
            "tool-response": "tool_result",
        }
        asset_id = "agent.opspilot"
        if mcp_server:
            asset_id = "mcp." + mcp_server
        record = {
            "event_id": event_id,
            "instance_id": session_id,
            "trace_id": session_id,
            "timestamp": datetime.now(UTC).isoformat(),
            "stage": stage_map[stage],
            "asset_id": asset_id,
            "direction": str(payload.get("direction") or stage),
            "tool": tool,
            "payload": redact_evidence(payload),
            "decision": redact_evidence(verdict),
            "raw_ref": f"runtime:{event_id}",
        }
        target = Path(self.evidence_path)
        target.parent.mkdir(parents=True, exist_ok=True)
        try:
            with _EVIDENCE_LOCK, target.open("a", encoding="utf-8", newline="\n") as stream:
                stream.write(json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n")
        except OSError:
            # Evidence persistence is deliberately non-blocking. The gateway
            # decision remains authoritative; report generation will expose a
            # missing evidence file instead of interrupting normal traffic.
            return


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
