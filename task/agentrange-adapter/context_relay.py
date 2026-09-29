"""Tiny in-network relay for authenticated AgentRange request context.

The range application intentionally owns its own HTTP clients and does not
forward user headers to every downstream call.  The adapter therefore keeps a
short-lived, session/trace-keyed authorization context outside the range
source tree.  This process has no host port and stores no request bodies.
"""

from __future__ import annotations

import json
import os
import threading
import time
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

MAX_ENTRIES = max(100, int(os.getenv("DC_CONTEXT_MAX_ENTRIES", "10000")))
DEFAULT_TTL = max(5, int(os.getenv("DC_CONTEXT_TTL_SECONDS", "120")))
MAX_BODY = 16 * 1024
_lock = threading.Lock()
_contexts: dict[str, tuple[float, dict]] = {}


def _key(session_id: str, trace_id: str) -> str:
    return f"{session_id}\x00{trace_id}"


def _clean() -> None:
    now = time.monotonic()
    expired = [key for key, (deadline, _value) in _contexts.items() if deadline <= now]
    for key in expired:
        _contexts.pop(key, None)
    if len(_contexts) <= MAX_ENTRIES:
        return
    for key, _item in sorted(_contexts.items(), key=lambda item: item[1][0])[: len(_contexts) - MAX_ENTRIES]:
        _contexts.pop(key, None)


def _json_response(handler: BaseHTTPRequestHandler, status: int, payload: dict) -> None:
    body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Cache-Control", "no-store")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


class ContextRelayHandler(BaseHTTPRequestHandler):
    server_version = "DefenseClawAgentRangeContextRelay/1.0"

    def log_message(self, fmt: str, *args: object) -> None:
        # Do not log principals, tenant names, tokens, or request bodies.
        return

    def do_PUT(self) -> None:
        if self.path != "/v1/context":
            _json_response(self, HTTPStatus.NOT_FOUND, {"error": "not found"})
            return
        length = int(self.headers.get("Content-Length") or "0")
        if length <= 0 or length > MAX_BODY:
            _json_response(self, HTTPStatus.BAD_REQUEST, {"error": "invalid body"})
            return
        try:
            body = json.loads(self.rfile.read(length))
        except (json.JSONDecodeError, UnicodeDecodeError):
            _json_response(self, HTTPStatus.BAD_REQUEST, {"error": "invalid json"})
            return
        session_id = str(body.get("session_id") or "").strip()
        trace_id = str(body.get("trace_id") or "").strip()
        context = body.get("context")
        if not session_id or not trace_id or not isinstance(context, dict):
            _json_response(self, HTTPStatus.BAD_REQUEST, {"error": "session_id, trace_id and context required"})
            return
        ttl = body.get("ttl_seconds", DEFAULT_TTL)
        try:
            ttl = min(DEFAULT_TTL, max(5, int(ttl)))
        except (TypeError, ValueError):
            ttl = DEFAULT_TTL
        with _lock:
            _clean()
            _contexts[_key(session_id, trace_id)] = (time.monotonic() + ttl, context)
        _json_response(self, HTTPStatus.NO_CONTENT, {})

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path != "/v1/context":
            _json_response(self, HTTPStatus.NOT_FOUND, {"error": "not found"})
            return
        query = parse_qs(parsed.query)
        session_id = str((query.get("session_id") or [""])[0]).strip()
        trace_id = str((query.get("trace_id") or [""])[0]).strip()
        if not session_id:
            _json_response(self, HTTPStatus.BAD_REQUEST, {"error": "session_id required"})
            return
        with _lock:
            _clean()
            item = _contexts.get(_key(session_id, trace_id)) if trace_id else None
            if item is None and not trace_id:
                candidates = [candidate for key, candidate in _contexts.items() if key.startswith(session_id + "\x00")]
                item = max(candidates, key=lambda candidate: candidate[0], default=None)
        if item is None:
            _json_response(self, HTTPStatus.NOT_FOUND, {"error": "context not found"})
            return
        _json_response(self, HTTPStatus.OK, {"context": item[1]})

    def do_DELETE(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path != "/v1/context":
            _json_response(self, HTTPStatus.NOT_FOUND, {"error": "not found"})
            return
        query = parse_qs(parsed.query)
        session_id = str((query.get("session_id") or [""])[0]).strip()
        trace_id = str((query.get("trace_id") or [""])[0]).strip()
        if session_id and trace_id:
            with _lock:
                _contexts.pop(_key(session_id, trace_id), None)
        _json_response(self, HTTPStatus.NO_CONTENT, {})


def main() -> None:
    port = int(os.getenv("DC_CONTEXT_RELAY_PORT", "9101"))
    server = ThreadingHTTPServer(("0.0.0.0", port), ContextRelayHandler)
    server.serve_forever()


if __name__ == "__main__":
    main()
