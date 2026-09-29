 # Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

"""HTTP sidecar used by the generated AgentRange Compose overlay.

The script intentionally depends only on the Python standard library so it can
run inside ``python:3.12-slim`` without baking a custom range image.
"""

from __future__ import annotations

import json
import os
import re
import sys
import threading
import time
import base64
from concurrent.futures import Future, ThreadPoolExecutor
from contextlib import contextmanager
from http.client import HTTPConnection, HTTPException, HTTPSConnection
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from io import BytesIO
from queue import Empty, Full, LifoQueue
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode, urlsplit
from urllib.request import Request, urlopen as _urllib_urlopen
from uuid import uuid4
 
HOP_BY_HOP_HEADERS = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
}
APP_FRAMES_HEADER = "X-DefenseClaw-App-Frames"
MAX_APP_FRAMES_HEADER_BYTES = 2048
MAX_APP_FRAMES = 12
APP_FRAME_MODULE = re.compile(r"^(?:api|skills)(?:\.[A-Za-z_][A-Za-z0-9_]*)+$")
APP_FRAME_FUNCTION = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

# Request-local operation metadata; no audit data is used to construct events.
from contextvars import ContextVar
_runtime_request = ContextVar("agentrange_runtime_request", default=None)
_runtime_result_executor = ThreadPoolExecutor(max_workers=8, thread_name_prefix="runtime-result")
_audit_executor = ThreadPoolExecutor(max_workers=16, thread_name_prefix="runtime-audit")
_audit_pending = 0
_audit_pending_lock = threading.Lock()
_gateway_pools: dict[tuple[str, str, int], LifoQueue[HTTPConnection]] = {}
_gateway_pools_lock = threading.Lock()

MAX_FORWARD_BODY_BYTES = int(os.getenv("DC_MAX_FORWARD_BODY_BYTES", str(10 * 1024 * 1024)))
MAX_INSPECT_TEXT_BYTES = int(os.getenv("DC_MAX_INSPECT_TEXT_BYTES", str(256 * 1024)))
MAX_AGENT_STACK_HEADER_BYTES = 4096
MAX_AGENT_STACK_FRAMES = 16
_STACK_FUNCTION_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
UPSTREAM_TIMEOUT_SECONDS = float(os.getenv("DC_UPSTREAM_TIMEOUT_SECONDS", "30"))


def parse_agent_stack_header(value: str | None) -> list[dict[str, str | int]]:
    """Validate OpsPilot's bounded, project-relative runtime stack evidence."""
    if not value or len(value.encode("utf-8", errors="ignore")) > MAX_AGENT_STACK_HEADER_BYTES:
        return []
    try:
        rows = json.loads(value)
    except (TypeError, ValueError):
        return []
    if not isinstance(rows, list):
        return []
    frames: list[dict[str, str | int]] = []
    for row in rows[:MAX_AGENT_STACK_FRAMES]:
        if not isinstance(row, dict):
            continue
        file = row.get("file")
        function = row.get("function")
        line = row.get("line")
        if not isinstance(file, str) or not isinstance(function, str):
            continue
        if not isinstance(line, int) or isinstance(line, bool) or not 1 <= line <= 10_000_000:
            continue
        if file.startswith("/") or "\\" in file or ":" in file or ".." in file.split("/"):
            continue
        if not file.startswith(("api/", "policy/", "skills/")):
            continue
        if not _STACK_FUNCTION_RE.fullmatch(function):
            continue
        frames.append({"file": file[:256], "function": function, "line": line})
    return frames


def getenv(name: str, default: str = "") -> str:
    return os.getenv(name, default).strip()


def gateway_base() -> str:
    return getenv("DC_GATEWAY_BASE", "http://host.docker.internal:18970").rstrip("/")


def _gateway_pool(url: str) -> tuple[LifoQueue[HTTPConnection], tuple[str, str, int]]:
    parsed = urlsplit(url)
    key = (parsed.scheme, parsed.hostname or "", parsed.port or (443 if parsed.scheme == "https" else 80))
    with _gateway_pools_lock:
        pool = _gateway_pools.setdefault(key, LifoQueue(maxsize=32))
    return pool, key


@contextmanager
def _gateway_urlopen(request: Request, timeout: float):
    pool, (scheme, host, port) = _gateway_pool(request.full_url)
    parsed = urlsplit(request.full_url)
    path = parsed.path + ("?" + parsed.query if parsed.query else "")
    deadline = time.monotonic() + timeout
    for attempt in range(2):
        try:
            connection = pool.get_nowait()
            reused = True
        except Empty:
            connection = (HTTPSConnection if scheme == "https" else HTTPConnection)(host, port)
            reused = False
        remaining = max(0.001, deadline - time.monotonic())
        connection.timeout = remaining
        if connection.sock is not None:
            connection.sock.settimeout(remaining)
        try:
            connection.request(request.get_method(), path, body=request.data, headers=dict(request.header_items()))
            response = connection.getresponse()
        except (OSError, HTTPException) as exc:
            connection.close()
            if reused and attempt == 0 and time.monotonic() < deadline:
                continue
            raise URLError(exc) from exc
        if response.status >= 400:
            body = response.read()
            connection.close()
            raise HTTPError(request.full_url, response.status, response.reason, response.headers, BytesIO(body))
        try:
            yield response
            response.read()
        except BaseException:
            connection.close()
            raise
        else:
            if response.will_close or connection.sock is None:
                connection.close()
            else:
                try:
                    pool.put_nowait(connection)
                except Full:
                    connection.close()
        return


def urlopen(request: Request, *, timeout: float):
    target = urlsplit(request.full_url)
    gateway = urlsplit(gateway_base())
    if (target.scheme, target.netloc) == (gateway.scheme, gateway.netloc):
        return _gateway_urlopen(request, timeout)
    return _urllib_urlopen(request, timeout=timeout)


def fail_mode() -> str:
    mode = getenv("DC_FAIL_MODE", "open").lower()
    return "closed" if mode in {"closed", "fail-closed", "fail_closed"} else "open"


def inspect_timeout() -> float:
    raw = getenv("DC_INSPECT_TIMEOUT_MS", "400")
    try:
        return max(1, int(raw)) / 1000.0
    except ValueError:
        return 0.4


def inspection_bypassed() -> bool:
    """Disable gateway calls only for an explicit benchmark baseline.

    The flag is opt-in and remains false for normal observe/action operation;
    it lets a same-topology resource window measure proxy cost without
    silently changing production enforcement behavior.
    """
    return getenv("DC_BYPASS_INSPECTION", "0").lower() in {"1", "true", "yes"}


def baseline_allow_verdict() -> dict[str, Any]:
    return {
        "action": "allow",
        "raw_action": "allow",
        "severity": "NONE",
        "reason": "benchmark baseline inspection bypass",
        "would_block": False,
    }


def runtime_result_timeout() -> float:
    raw = getenv("DC_RUNTIME_RESULT_TIMEOUT_MS", "250")
    try:
        return max(25, int(raw)) / 1000.0
    except ValueError:
        return 0.25


def connector_name() -> str:
    return getenv("DC_CONNECTOR", "agentrange") or "agentrange"


def json_loads_maybe(data: bytes) -> Any:
    if not data:
        return None
    try:
        return json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None


def text_snippet(data: bytes) -> str:
    if not data:
        return ""
    data = data[:MAX_INSPECT_TEXT_BYTES]
    return data.decode("utf-8", errors="replace")


def inspection_response_body(kind: str, path: str, status: int, body: bytes) -> bytes:
    """Keep issued credentials out of response inspection and audit records."""
    auth_paths = {"langflow": "/api/v1/auto_login", "opspilot": "/login"}
    if status < 200 or status >= 300 or path != auth_paths.get(kind):
        return body
    payload = json_loads_maybe(body)
    if not isinstance(payload, dict):
        return body
    sanitized = dict(payload)
    for key in ("access_token", "refresh_token"):
        if isinstance(sanitized.get(key), str):
            sanitized[key] = "[issued credential]"
    return dumps_compact(sanitized).encode("utf-8")


def dumps_compact(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def extract_session(headers: Any) -> str:
    for key in ("X-Instance-Id", "X-DC-Session-Id", "X-DefenseClaw-Session-Id", "X-Request-Id"):
        value = headers.get(key)
        if value:
            return value
    return f"agentrange-{uuid4()}"


def extract_app_frames(headers: Any) -> list[dict[str, Any]]:
    encoded = str(headers.get(APP_FRAMES_HEADER) or "")
    if not encoded or len(encoded) > MAX_APP_FRAMES_HEADER_BYTES:
        return []
    try:
        decoded = base64.b64decode(encoded, altchars=b"-_", validate=True)
        frames = json.loads(decoded)
    except (ValueError, UnicodeError):
        return []
    if not isinstance(frames, list) or len(frames) > MAX_APP_FRAMES:
        return []
    normalized = []
    for frame in frames:
        if not isinstance(frame, dict):
            return []
        module, function, line = frame.get("module"), frame.get("function"), frame.get("line")
        if (not isinstance(module, str) or not APP_FRAME_MODULE.fullmatch(module)
                or not isinstance(function, str) or not APP_FRAME_FUNCTION.fullmatch(function)
                or type(line) is not int or not 0 < line <= 1_000_000):
            return []
        normalized.append({"module": module, "function": function, "line": line})
    return normalized


def extract_trace(headers: Any) -> str:
    for key in ("X-DefenseClaw-Trace-Id", "X-DC-Trace-Id", "traceparent", "X-Request-Id"):
        value = headers.get(key)
        if value:
            return value
    return f"trace-{uuid4()}"


def extract_authorization_context(headers: Any) -> dict[str, Any] | None:
    """Read adapter-supplied authenticated scope for downstream policy checks.

    The application adapter has already validated the JWT before these
    headers are emitted.  The sidecar only transports the normalized shape;
    it never uses scenario labels or trajectory data to construct it.
    """
    subject = str(headers.get("X-Acting-User") or "").strip()
    role = str(headers.get("X-Acting-Role") or "").strip()
    raw_scope = str(headers.get("X-Acting-Scope") or "").strip()
    if not subject and not raw_scope:
        return None
    try:
        scope = json.loads(raw_scope) if raw_scope else {}
    except json.JSONDecodeError:
        return None
    if not isinstance(scope, dict):
        return None
    return {"principal": {"sub": subject, "role": role, "scope": scope}}


def _decode_jwt_claims(token: str) -> dict[str, Any] | None:
    """Decode claims for transport after the target app authenticates them.

    The adapter does not make an authorization decision from this payload and
    never forwards it as a credential.  The range application remains the
    authority that verifies the JWT signature and expiry; this unverified
    projection only lets downstream sidecars correlate the already-authenticated
    request.  Invalid or malformed tokens produce no context.
    """
    parts = token.strip().split(".")
    if len(parts) != 3:
        return None
    try:
        padded = parts[1] + "=" * (-len(parts[1]) % 4)
        claims = json.loads(base64.urlsafe_b64decode(padded.encode("ascii")))
    except (ValueError, UnicodeError, json.JSONDecodeError):
        return None
    if not isinstance(claims, dict):
        return None
    subject = str(claims.get("sub") or "").strip()
    scope = claims.get("scope")
    if not subject or not isinstance(scope, dict):
        return None
    role = str(claims.get("role") or "").strip()
    return {"principal": {"sub": subject, "role": role, "scope": scope}}


def extract_jwt_authorization_context(headers: Any) -> dict[str, Any] | None:
    authorization = str(headers.get("Authorization") or "").strip()
    if not authorization.lower().startswith("bearer "):
        return None
    return _decode_jwt_claims(authorization.split(" ", 1)[1])


def context_relay_url() -> str:
    return getenv("DC_CONTEXT_RELAY_URL").rstrip("/")


def _relay_request(
    method: str,
    session_id: str,
    trace_id: str,
    context: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    base = context_relay_url()
    if not base or not session_id or (method != "GET" and not trace_id):
        return None
    query = urlencode({"session_id": session_id, "trace_id": trace_id})
    url = f"{base}/v1/context"
    data = None
    if method == "PUT":
        data = json.dumps({"session_id": session_id, "trace_id": trace_id, "context": context}, separators=(",", ":")).encode("utf-8")
    elif method == "GET":
        url += "?" + query
    request = Request(url, data=data, method=method)
    request.add_header("Content-Type", "application/json")
    try:
        with urlopen(request, timeout=min(0.25, inspect_timeout())) as response:
            parsed = json_loads_maybe(response.read())
            return parsed if isinstance(parsed, dict) else {}
    except (HTTPError, URLError, TimeoutError, OSError):
        return None


def relay_authorization_context(session_id: str, trace_id: str, context: dict[str, Any] | None) -> dict[str, Any] | None:
    """Register an ingress context or retrieve it in a downstream sidecar."""
    if context:
        _relay_request("PUT", session_id, trace_id, context)
        return context
    # Internal clients commonly retain the stable session but mint a new
    # trace id. Querying by session first avoids a failed exact lookup on every
    # downstream request while still keeping the relay scoped to one run.
    response = _relay_request("GET", session_id, "")
    value = response.get("context") if response else None
    if isinstance(value, dict):
        return value
    response = _relay_request("GET", session_id, trace_id)
    value = response.get("context") if response else None
    return value if isinstance(value, dict) else None


def authed_request(url: str, payload: dict[str, Any], *, timeout: float) -> Request:
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    request = Request(url, data=body, method="POST")
    request.add_header("Content-Type", "application/json")
    request.add_header("X-DefenseClaw-Client", "agentrange-sidecar")
    token = getenv("DC_GATEWAY_TOKEN") or getenv("DEFENSECLAW_GATEWAY_TOKEN")
    state = _runtime_request.get()
    if state:
        context = state["context"]
        request.add_header("X-DefenseClaw-Session-Id", context["session_id"])
        request.add_header("X-DefenseClaw-Trace-Id", context["trace_id"])
        request.add_header("X-Instance-Id", context["session_id"])
    if token:
        request.add_header("Authorization", f"Bearer {token}")
        request.add_header("X-DefenseClaw-Token", token)
        request.add_header("X-DC-Auth", f"Bearer {token}")
        request.add_header("X-DefenseClaw-Connector", connector_name())
    return request


def inspect_call(endpoint: str, payload: dict[str, Any]) -> tuple[dict[str, Any] | None, str | None]:
    state = _runtime_request.get()
    if state:
        context = dict(state["context"])
        context["event_id"] = str(uuid4())
        if endpoint.endswith("/tool"):
            context["phase"] = "pre"
            context["tool_name"] = str(payload.get("tool") or "")
            context["operation"] = "tool.inspect"
        elif endpoint.endswith("/tool-response"):
            context["phase"] = "post"
            context["tool_name"] = str(payload.get("tool") or "")
        payload = dict(payload, runtime_context=context)
        state["inspection_ids"].append(context["event_id"])
        check = {"endpoint": endpoint, "payload": payload}
        state["pending_checks"].append(check)
    url = f"{gateway_base()}{endpoint}"
    request = authed_request(url, payload, timeout=inspect_timeout())
    timeout = inspect_timeout()
    retryable = state is not None and timeout >= 0.35
    deadline = time.monotonic() + timeout
    last_error = "inspection timeout"
    # A second delivery uses the same event ID, so Gateway persistence stays idempotent.
    for attempt in range(2 if retryable else 1):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        attempt_timeout = min(0.25, remaining) if retryable and attempt == 0 else remaining
        try:
            with urlopen(request, timeout=attempt_timeout) as response:
                raw = response.read()
                if response.headers.get("X-DefenseClaw-Runtime-Status") in {"failed", "unavailable"}:
                    sys.stderr.write("[runtime] inspection persistence/evaluation failed; see gateway log\n")
                elif state:
                    state["pending_checks"].remove(check)
        except HTTPError as exc:
            return None, f"HTTP {exc.code}"
        except (URLError, TimeoutError, OSError) as exc:
            last_error = str(exc)
            continue
        parsed = json_loads_maybe(raw)
        if isinstance(parsed, dict):
            return parsed, None
        return None, "inspect response was not JSON"
    return None, last_error


def should_block(verdict: dict[str, Any] | None, error: str | None) -> bool:
    if error:
        return fail_mode() == "closed"
    if not verdict:
        return False
    return str(verdict.get("action", "")).lower() == "block"


def verdict_action(verdict: dict[str, Any] | None, error: str | None) -> str:
    if error:
        return "inspect_unavailable"
    if not verdict:
        return "allow"
    return str(verdict.get("action") or "allow")


def verdict_severity(verdict: dict[str, Any] | None, error: str | None) -> str:
    if error:
        return "HIGH" if fail_mode() == "closed" else "WARN"
    if not verdict:
        return "INFO"
    return str(verdict.get("severity") or "INFO")


def verdict_reason(verdict: dict[str, Any] | None, error: str | None) -> str:
    if error:
        return error
    if not verdict:
        return ""
    return str(verdict.get("reason") or "")


def emit_audit_event(
    *,
    stage: str,
    session_id: str,
    trace_id: str,
    meta: dict[str, Any],
    verdict: dict[str, Any] | None,
    error: str | None,
    latency_ms: int,
    response_body: bytes = b"",
) -> Future[Any] | None:
    authorization_context = (_runtime_request.get() or {}).get("authorization_context") or {}
    principal = authorization_context.get("principal") if isinstance(authorization_context, dict) else {}
    principal = principal if isinstance(principal, dict) else {}
    scope = principal.get("scope") if isinstance(principal.get("scope"), dict) else {}
    decision = verdict_action(verdict, error)
    severity = verdict_severity(verdict, error)
    structured = {
        # AgentRange's runner uses X-Instance-Id as the stable benchmark key;
        # keep it explicit so post-run scoring never guesses from trace data.
        "instance_id": session_id,
        "session_id": session_id,
        "trace_id": trace_id,
        "stage": stage,
        "call_id": (_runtime_request.get() or {}).get("context", {}).get("call_id", ""),
        "inspection_event_ids": (_runtime_request.get() or {}).get("inspection_ids", []),
        "raw_action": (verdict or {}).get("raw_action", ""),
        "mode": (verdict or {}).get("mode", ""),
        "would_block": (verdict or {}).get("would_block", False),
        "source": meta.get("source", ""),
        "destination": meta.get("destination", ""),
        "actor": "defenseclaw-agentrange-sidecar",
        "tenant": meta.get("tenant", ""),
        "authorization_context": authorization_context,
        "app_frames": (_runtime_request.get() or {}).get("app_frames", []),
        "app_frames_source": "client_reported" if (_runtime_request.get() or {}).get("app_frames") else "",
        "principal_subject": str(principal.get("sub") or ""),
        "principal_scope": scope,
        "prompt": meta.get("prompt", ""),
        "model": meta.get("model", ""),
        "tool_name": meta.get("tool_name", ""),
        "mcp_server": meta.get("mcp_server", ""),
        "request_body": meta.get("request_body", ""),
        "response_body": text_snippet(response_body),
        "decision": decision,
        "severity": severity,
        "reason": verdict_reason(verdict, error),
        "latency_ms": latency_ms,
        "raw_ref": meta.get("raw_ref", ""),
        "proxy_kind": getenv("DC_PROXY_KIND"),
        "http_method": meta.get("method", ""),
        "http_path": meta.get("path", ""),
    }
    payload = {
        "action": f"agentrange-runtime-{stage}",
        "target": str(meta.get("target") or meta.get("destination") or getenv("DC_PROXY_KIND") or "agentrange"),
        "actor": "defenseclaw-agentrange-sidecar",
        "details": f"stage={stage} decision={decision} destination={structured['destination']}",
        "severity": severity,
        "trace_id": trace_id,
        "session_id": session_id,
        "instance_id": session_id,
        "agent_name": "AgentRange",
        "connector": connector_name(),
        "destination_app": structured["destination"],
        "tool_name": structured["tool_name"],
        "structured": structured,
    }
    global _audit_pending
    with _audit_pending_lock:
        _audit_pending += 1
    return _audit_executor.submit(_deliver_audit_event, payload)


def _deliver_audit_event(payload: dict[str, Any]) -> None:
    """Persist audit evidence off the user-request critical path."""
    global _audit_pending
    try:
        request = authed_request(f"{gateway_base()}/audit/event", payload, timeout=inspect_timeout())
        with urlopen(request, timeout=inspect_timeout()):
            pass
    except (HTTPError, URLError, TimeoutError, OSError) as exc:
        sys.stderr.write(f"[audit] delivery failed: {type(exc).__name__}\n")
    finally:
        with _audit_pending_lock:
            _audit_pending = max(0, _audit_pending - 1)


def audit_pending() -> int:
    with _audit_pending_lock:
        return _audit_pending


def _deliver_runtime_result(state: dict[str, Any], outcome: str, status: int) -> None:
    context = dict(state["context"], instance_id=state["context"].get("instance_id", state["context"]["session_id"]), phase="result", event_id=state["result_id"])
    payload = {"runtime_context": context, "outcome": outcome,
               "http_status": status, "inspection_event_ids": state["inspection_ids"]}
    # Result delivery is independent of audit and happens after response delivery.
    # Two attempts reuse the same event id; failures are visible, never silent.
    for attempt in range(2):
        try:
            # Retry failed check persistence after response delivery, with the
            # same original payload/id. Payloads stay request-local in memory;
            # no raw input is written to an outbox or audit-derived event.
            for check in list(state["pending_checks"]):
                request = authed_request(f"{gateway_base()}{check['endpoint']}", check["payload"], timeout=runtime_result_timeout())
                with urlopen(request, timeout=runtime_result_timeout()) as response:
                    response.read()
                    if response.headers.get("X-DefenseClaw-Runtime-Status") in {"failed", "unavailable"}:
                        raise OSError("runtime persistence unavailable")
                state["pending_checks"].remove(check)
            request = authed_request(f"{gateway_base()}/api/v1/runtime-results", payload, timeout=runtime_result_timeout())
            with urlopen(request, timeout=runtime_result_timeout()) as response:
                response.read()
            return
        except HTTPError as exc:
            sys.stderr.write(f"[runtime] result delivery attempt={attempt + 1} failed: HTTP {exc.code}\n")
        except (URLError, TimeoutError, OSError) as exc:
            sys.stderr.write(f"[runtime] result delivery attempt={attempt + 1} failed: {type(exc).__name__}\n")


def emit_runtime_result(outcome: str, status: int = 0) -> Future[Any] | None:
    state = _runtime_request.get()
    if not state:
        return
    # Result persistence is independent of the upstream response. Snapshot
    # request-local state before handing it to the bounded worker pool so a
    # slow audit endpoint cannot add its latency to the user request.
    snapshot = {
        "context": dict(state["context"]),
        "result_id": state["result_id"],
        "inspection_ids": list(state["inspection_ids"]),
        "pending_checks": list(state["pending_checks"]),
    }
    state["pending_checks"].clear()
    return _runtime_result_executor.submit(_deliver_runtime_result, snapshot, outcome, status)


def inspect_request(content: str, session_id: str, model: str = "") -> tuple[dict[str, Any] | None, str | None]:
    return inspect_call(
        "/api/v1/inspect/request",
        {"content": content[:MAX_INSPECT_TEXT_BYTES], "session_id": session_id, "model": model},
    )


def inspect_response(content: str, session_id: str, model: str = "") -> tuple[dict[str, Any] | None, str | None]:
    return inspect_call(
        "/api/v1/inspect/response",
        {"content": content[:MAX_INSPECT_TEXT_BYTES], "session_id": session_id, "model": model},
    )


def inspect_tool(
    tool: str,
    args: Any,
    session_id: str,
    *,
    mcp_server: str = "",
    content: str = "",
) -> tuple[dict[str, Any] | None, str | None]:
    payload: dict[str, Any] = {
        "tool": tool,
        "args": args,
        "content": content[:MAX_INSPECT_TEXT_BYTES],
        "session_id": session_id,
        "connector": connector_name(),
    }
    if mcp_server:
        payload["mcp_server_name"] = mcp_server
    state = _runtime_request.get()
    if state and state.get("authorization_context"):
        payload["context"] = state["authorization_context"]
    return inspect_call("/api/v1/inspect/tool", payload)


def inspect_tool_response(tool: str, output: Any, session_id: str) -> tuple[dict[str, Any] | None, str | None]:
    return inspect_call(
        "/api/v1/inspect/tool-response",
        {"tool": tool, "output": output, "session_id": session_id},
    )


def extract_opspilot_prompt(data: bytes) -> str:
    parsed = json_loads_maybe(data)
    if isinstance(parsed, dict):
        for key in ("prompt", "query", "question", "input", "user_input"):
            value = parsed.get(key)
            if isinstance(value, str) and value.strip():
                return value
        messages = parsed.get("messages")
        if isinstance(messages, list):
            return dumps_compact(messages)
    return text_snippet(data)


def extract_llm_messages(data: bytes) -> tuple[str, str]:
    parsed = json_loads_maybe(data)
    if not isinstance(parsed, dict):
        return text_snippet(data), ""
    model = str(parsed.get("model") or "")
    messages = parsed.get("messages")
    if isinstance(messages, list):
        return dumps_compact(messages), model
    return dumps_compact(parsed), model


def iter_openai_tool_calls(data: bytes) -> list[tuple[str, Any]]:
    parsed = json_loads_maybe(data)
    if not isinstance(parsed, dict):
        return []
    out: list[tuple[str, Any]] = []
    for choice in parsed.get("choices") or []:
        if not isinstance(choice, dict):
            continue
        message = choice.get("message")
        if not isinstance(message, dict):
            continue
        for call in message.get("tool_calls") or []:
            if not isinstance(call, dict):
                continue
            function = call.get("function")
            if not isinstance(function, dict):
                continue
            name = str(function.get("name") or "tool_call")
            args_raw = function.get("arguments")
            args = args_raw
            if isinstance(args_raw, str):
                try:
                    args = json.loads(args_raw)
                except json.JSONDecodeError:
                    args = args_raw
            out.append((name, args))
    return out


def parse_mcp_request(data: bytes) -> tuple[str, str, Any]:
    parsed = json_loads_maybe(data)
    if not isinstance(parsed, dict):
        return "", "", None
    method = str(parsed.get("method") or "")
    params = parsed.get("params")
    tool = ""
    args: Any = params
    if isinstance(params, dict):
        tool = str(params.get("name") or params.get("tool") or "")
        args = params.get("arguments", params.get("args", params))
    return method, tool, args


def mcp_target_for_path(path: str, targets: dict[str, str]) -> tuple[str, str, str] | None:
    clean = path.split("?", 1)[0].strip("/")
    if not clean:
        return None
    service, _, rest = clean.partition("/")
    if service not in targets:
        return None
    downstream = f"/{rest}" if rest else "/mcp"
    return service, targets[service].rstrip("/"), downstream


def request_event_meta(handler: BaseHTTPRequestHandler, body: bytes, target_url: str) -> dict[str, Any]:
    kind = getenv("DC_PROXY_KIND")
    meta = {
        "source": "opspilot-app",
        "destination": getenv("DC_TARGET_BASE") or target_url,
        "target": kind or "agentrange",
        "method": getattr(handler, "command", ""),
        "path": getattr(handler, "path", ""),
        "request_body": text_snippet(body),
        "raw_ref": target_url,
    }
    if kind in {"opspilot", "langflow"}:
        meta["source"] = "host"
    if kind == "opspilot":
        meta["prompt"] = extract_opspilot_prompt(body)
        meta["destination"] = "opspilot-app"
        meta["target"] = "opspilot-app"
    elif kind == "langflow":
        meta["prompt"] = text_snippet(body)
        meta["destination"] = "langflow"
        meta["target"] = "langflow"
    elif kind == "llm":
        content, model = extract_llm_messages(body)
        meta["prompt"] = content
        meta["model"] = model
        meta["destination"] = "llm-stub"
        meta["target"] = "llm-stub"
    elif kind == "mcp":
        service = handler.path.strip("/").split("/", 1)[0]
        _method, tool, _args = parse_mcp_request(body)
        meta["destination"] = service
        meta["target"] = service
        meta["mcp_server"] = service
        meta["tool_name"] = tool
    return meta


def set_context_tenant(meta: dict[str, Any], authorization_context: dict[str, Any] | None) -> None:
    if not authorization_context:
        return
    principal = authorization_context.get("principal")
    if not isinstance(principal, dict):
        return
    scope = principal.get("scope")
    if isinstance(scope, dict) and scope.get("tenant"):
        meta["tenant"] = str(scope["tenant"])


def build_target_url(handler: BaseHTTPRequestHandler) -> tuple[str | None, str]:
    kind = getenv("DC_PROXY_KIND")
    if kind == "mcp":
        targets = json.loads(getenv("DC_MCP_TARGETS", "{}") or "{}")
        match = mcp_target_for_path(handler.path, targets)
        if not match:
            return None, "unknown MCP target"
        _service, base, downstream = match
        query = ""
        if "?" in handler.path:
            query = "?" + handler.path.split("?", 1)[1]
        return f"{base}{downstream}{query}", ""

    base = getenv("DC_TARGET_BASE").rstrip("/")
    if not base:
        return None, "DC_TARGET_BASE is not configured"
    return f"{base}{handler.path}", ""


def response_json(status: int, payload: dict[str, Any]) -> tuple[int, list[tuple[str, str]], bytes]:
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    return status, [("Content-Type", "application/json")], body


class AgentRangeProxyHandler(BaseHTTPRequestHandler):
    server_version = "DefenseClawAgentRangeSidecar/1.0"
    protocol_version = "HTTP/1.1"

    def do_GET(self) -> None:
        if self.path.split("?", 1)[0] == "/health":
            self._send(*response_json(HTTPStatus.OK, {"status": "ok", "pending_audit_events": audit_pending()}))
            return
        self.handle_proxy()

    def do_POST(self) -> None:
        self.handle_proxy()

    def do_PUT(self) -> None:
        self.handle_proxy()

    def do_PATCH(self) -> None:
        self.handle_proxy()

    def do_DELETE(self) -> None:
        self.handle_proxy()

    def do_OPTIONS(self) -> None:
        self.handle_proxy()

    def log_message(self, fmt: str, *args: Any) -> None:
        timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        sys.stderr.write(f"[{timestamp}] {fmt % args}\n")

    def handle_proxy(self) -> None:
        token = _runtime_request.set(None)
        try:
            self._handle_proxy()
        finally:
            _runtime_request.reset(token)

    def _handle_proxy(self) -> None:
        session_id = extract_session(self.headers)
        trace_id = extract_trace(self.headers)
        self._trace_id = trace_id
        body = self._read_body()
        if body is None:
            self._send(*response_json(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, {"error": "request body too large"}))
            return

        target_url, error = build_target_url(self)
        if error or not target_url:
            self._send(*response_json(HTTPStatus.BAD_GATEWAY, {"error": error or "no target URL"}))
            return

        meta = request_event_meta(self, body, target_url)
        authorization_context = extract_authorization_context(self.headers)
        # The public ingress receives the bearer token; downstream requests
        # from the range app retain only session/trace headers.  Decode the
        # claims for correlation after the app validates the same token, then
        # use the relay to make the context available to LLM/MCP sidecars.
        if getenv("DC_PROXY_KIND") in {"opspilot", "langflow"}:
            authorization_context = extract_jwt_authorization_context(self.headers) or authorization_context
        authorization_context = relay_authorization_context(session_id, trace_id, authorization_context)
        set_context_tenant(meta, authorization_context)
        app_frames = extract_app_frames(self.headers) if getenv("DC_PROXY_KIND") in {"llm", "mcp", "langflow"} else []
        stack_frames = (
            parse_agent_stack_header(self.headers.get("X-DefenseClaw-Agent-Stack"))
            if getenv("DC_PROXY_KIND") == "mcp"
            else []
        )
        context = {
            "connector": connector_name(), "instance_id": session_id, "session_id": session_id, "trace_id": trace_id,
            "call_id": str(uuid4()), "event_id": str(uuid4()), "phase": "pre",
            "proxy_kind": getenv("DC_PROXY_KIND"), "operation": "http.request",
            "tool_name": meta.get("tool_name", ""), "mcp_server": meta.get("mcp_server", ""),
            "http_method": self.command, "http_path": self.path.split("?", 1)[0],
            "target": str(meta.get("target") or getenv("DC_PROXY_KIND")),
        }
        if stack_frames:
            context["stack_source"] = "python.traceback"
            context["stack_frames"] = stack_frames
        _runtime_request.set({
            "context": context,
            "result_id": str(uuid4()), "inspection_ids": [], "pending_checks": [],
            "authorization_context": authorization_context,
            "app_frames": app_frames,
        })
        started = time.monotonic()
        verdict, inspect_error = self._pre_inspect(session_id, body)
        emit_audit_event(
            stage="pre",
            session_id=session_id,
            trace_id=trace_id,
            meta=meta,
            verdict=verdict,
            error=inspect_error,
            latency_ms=int((time.monotonic() - started) * 1000),
        )
        if should_block(verdict, inspect_error):
            emit_audit_event(
                stage="block",
                session_id=session_id,
                trace_id=trace_id,
                meta=meta,
                verdict=verdict,
                error=inspect_error,
                latency_ms=int((time.monotonic() - started) * 1000),
            )
            self._send_block(verdict, inspect_error, phase="pre")
            emit_runtime_result("rejected")
            return

        status, headers, response_body = self._forward(target_url, body)
        inspected_response_body = inspection_response_body(
            getenv("DC_PROXY_KIND"), self.path.split("?", 1)[0], status, response_body
        )
        _runtime_request.get()["context"]["phase"] = "post"
        post_started = time.monotonic()
        post_verdict, post_error = self._post_inspect(session_id, inspected_response_body, status)
        emit_audit_event(
            stage="post",
            session_id=session_id,
            trace_id=trace_id,
            meta=meta,
            verdict=post_verdict,
            error=post_error,
            latency_ms=int((time.monotonic() - post_started) * 1000),
            response_body=inspected_response_body,
        )
        if should_block(post_verdict, post_error):
            emit_audit_event(
                stage="block",
                session_id=session_id,
                trace_id=trace_id,
                meta=meta,
                verdict=post_verdict,
                error=post_error,
                latency_ms=int((time.monotonic() - started) * 1000),
                response_body=inspected_response_body,
            )
            self._send_block(post_verdict, post_error, phase="post")
            emit_runtime_result("response_blocked", status)
            return

        self._send(status, headers, response_body)
        emit_runtime_result("forward_failed" if getattr(self, "_forward_failed", False) else "response_received", status)

    def _read_body(self) -> bytes | None:
        length_raw = self.headers.get("Content-Length") or "0"
        try:
            length = int(length_raw)
        except ValueError:
            length = 0
        if length > MAX_FORWARD_BODY_BYTES:
            return None
        return self.rfile.read(length) if length > 0 else b""

    def _pre_inspect(self, session_id: str, body: bytes) -> tuple[dict[str, Any] | None, str | None]:
        if inspection_bypassed():
            return baseline_allow_verdict(), None
        kind = getenv("DC_PROXY_KIND")
        if kind == "opspilot" and self.path.split("?", 1)[0] == "/run":
            return inspect_request(extract_opspilot_prompt(body), session_id)
        if kind == "langflow":
            content = f"{self.command} {self.path}\n{text_snippet(body)}"
            return inspect_request(content, session_id)
        if kind == "llm" and self.path.split("?", 1)[0].endswith("/chat/completions"):
            content, model = extract_llm_messages(body)
            return inspect_request(content, session_id, model=model)
        if kind == "mcp":
            service = self.path.strip("/").split("/", 1)[0]
            method, tool, args = parse_mcp_request(body)
            if method == "tools/call":
                return inspect_tool(tool or "mcp.tools/call", args, session_id, mcp_server=service)
            if method in {"tools/list", "initialize"}:
                return inspect_tool(f"mcp.{method}", args, session_id, mcp_server=service, content=text_snippet(body))
        return None, None

    def _post_inspect(
        self,
        session_id: str,
        response_body: bytes,
        status: int,
    ) -> tuple[dict[str, Any] | None, str | None]:
        if inspection_bypassed():
            return baseline_allow_verdict(), None
        kind = getenv("DC_PROXY_KIND")
        if kind == "opspilot" and self.path.split("?", 1)[0] == "/run":
            return inspect_response(text_snippet(response_body), session_id)
        if kind == "langflow":
            return inspect_response(f"HTTP {status}\n{text_snippet(response_body)}", session_id)
        if kind == "llm" and self.path.split("?", 1)[0].endswith("/chat/completions"):
            for tool, args in iter_openai_tool_calls(response_body):
                verdict, error = inspect_tool(tool, args, session_id)
                if should_block(verdict, error):
                    return verdict, error
            return inspect_response(text_snippet(response_body), session_id)
        if kind == "mcp":
            method, tool, _args = parse_mcp_request(getattr(self, "_last_request_body", b""))
            if method == "tools/call":
                output = json_loads_maybe(response_body)
                return inspect_tool_response(
                    tool or "mcp.tools/call",
                    output if output is not None else text_snippet(response_body),
                    session_id,
                )
        return None, None

    def _forward(self, target_url: str, body: bytes) -> tuple[int, list[tuple[str, str]], bytes]:
        self._last_request_body = body
        self._forward_failed = False
        request_body = body if body or self.command not in {"GET", "HEAD"} else None
        request = Request(target_url, data=request_body, method=self.command)
        for key, value in self.headers.items():
            if key.lower() in HOP_BY_HOP_HEADERS or key.lower() in {"host", APP_FRAMES_HEADER.lower()}:
                continue
            request.add_header(key, value)
        if _runtime_request.get():
            request.add_header("X-Instance-Id", _runtime_request.get()["context"]["session_id"])
            request.add_header("X-DefenseClaw-Session-Id", _runtime_request.get()["context"]["session_id"])
        request.add_header("X-DefenseClaw-Trace-Id", getattr(self, "_trace_id", extract_trace(self.headers)))
        try:
            with urlopen(request, timeout=UPSTREAM_TIMEOUT_SECONDS) as response:
                headers = [(key, value) for key, value in response.headers.items()]
                return response.status, headers, response.read()
        except HTTPError as exc:
            headers = [(key, value) for key, value in exc.headers.items()]
            return exc.code, headers, exc.read()
        except (URLError, TimeoutError, OSError) as exc:
            self._forward_failed = True
            return response_json(HTTPStatus.BAD_GATEWAY, {"error": f"upstream unavailable: {exc}"})

    def _send_block(self, verdict: dict[str, Any] | None, error: str | None, *, phase: str) -> None:
        payload = {
            "error": "blocked by DefenseClaw",
            "phase": phase,
            "verdict": verdict or {"action": "block", "reason": error or "inspect unavailable"},
        }
        self._send(*response_json(HTTPStatus.FORBIDDEN, payload))

    def _send(self, status: int, headers: list[tuple[str, str]], body: bytes) -> None:
        self.send_response(status)
        sent_content_type = False
        for key, value in headers:
            lower = key.lower()
            if lower in HOP_BY_HOP_HEADERS or lower in {"content-length", "content-encoding"}:
                continue
            if lower == "content-type":
                sent_content_type = True
            self.send_header(key, value)
        if not sent_content_type:
            self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)


def main() -> None:
    port_raw = getenv("DC_LISTEN_PORT", "8000")
    try:
        port = int(port_raw)
    except ValueError:
        port = 8000
    server = ThreadingHTTPServer(("0.0.0.0", port), AgentRangeProxyHandler)
    kind = getenv("DC_PROXY_KIND", "proxy")
    target = getenv("DC_TARGET_BASE") or getenv("DC_MCP_TARGETS")
    sys.stderr.write(f"[defenseclaw-agentrange] kind={kind} listen=0.0.0.0:{port} target={quote(target[:160])}\n")
    server.serve_forever()


if __name__ == "__main__":
    main()
