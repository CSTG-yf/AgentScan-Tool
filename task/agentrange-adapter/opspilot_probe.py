"""Optional OpsPilot call-site evidence for DefenseClaw's AgentRange sidecars."""

from __future__ import annotations

import base64
import json
import os
import posixpath
import sys
from functools import wraps
from urllib.parse import urlsplit

import requests

FRAME_HEADER = "X-DefenseClaw-App-Frames"
MAX_FRAMES = 12
MAX_HEADER_BYTES = 2048
_original_request = None
_wrapped_request = None


def _sidecar_targets() -> tuple[tuple[str, str, str], ...]:
    configured = [
        (os.getenv("LLM_BASE", ""), "defenseclaw-llm-proxy"),
        (os.getenv("LANGFLOW_BASE", ""), "defenseclaw-langflow-ingress"),
    ]
    configured.extend(
        (value, "defenseclaw-mcp-proxy") for key, value in os.environ.items() if key.startswith("MCP_")
    )
    targets = set()
    for url, expected_host in configured:
        try:
            parsed = urlsplit(url)
            if parsed.scheme not in {"http", "https"} or parsed.hostname != expected_host:
                continue
            if parsed.username or parsed.password:
                continue
            targets.add((parsed.scheme, parsed.netloc.lower(), parsed.path.rstrip("/") or "/"))
        except ValueError:
            continue
    return tuple(sorted(targets))


def _is_sidecar_request(url: str, targets: tuple[tuple[str, str, str], ...]) -> bool:
    try:
        parsed = urlsplit(url)
    except ValueError:
        return False
    if parsed.username or parsed.password:
        return False
    for scheme, netloc, prefix in targets:
        if parsed.scheme != scheme or parsed.netloc.lower() != netloc:
            continue
        if prefix == "/" or parsed.path == prefix or parsed.path.startswith(prefix + "/"):
            return True
    return False


def _frame_header() -> str:
    frames = []
    encoded = ""
    frame = sys._getframe(1)
    try:
        while frame is not None and len(frames) < MAX_FRAMES:
            filename = posixpath.normpath(frame.f_code.co_filename.replace("\\", "/"))
            if filename.startswith(("/app/api/", "/app/skills/")) and filename.endswith(".py"):
                candidate = frames + [{
                    "module": filename[len("/app/"):-3].replace("/", "."),
                    "function": frame.f_code.co_name,
                    "line": frame.f_lineno,
                }]
                value = base64.urlsafe_b64encode(
                    json.dumps(candidate, ensure_ascii=True, separators=(",", ":")).encode("ascii")
                ).decode("ascii")
                if len(value) > MAX_HEADER_BYTES:
                    break
                frames, encoded = candidate, value
            frame = frame.f_back
    finally:
        del frame
    return encoded


def install() -> bool:
    """Attach bounded call-site evidence to configured internal proxy requests."""
    global _original_request, _wrapped_request
    if _original_request is not None:
        return False
    targets = _sidecar_targets()
    original = requests.sessions.Session.request

    @wraps(original)
    def instrumented_request(session, method, url, **kwargs):
        if not _is_sidecar_request(str(url), targets):
            return original(session, method, url, **kwargs)
        headers = kwargs.get("headers")
        copied = {key: value for key, value in dict(headers or {}).items() if key.lower() != FRAME_HEADER.lower()}
        frames = _frame_header()
        if frames:
            copied[FRAME_HEADER] = frames
        if copied or headers is not None:
            kwargs["headers"] = copied
        return original(session, method, url, **kwargs)

    requests.sessions.Session.request = instrumented_request
    _original_request = original
    _wrapped_request = instrumented_request
    return True


def uninstall() -> None:
    """Restore the original request method when the probe owns the wrapper."""
    global _original_request, _wrapped_request
    if _original_request is not None and requests.sessions.Session.request is _wrapped_request:
        requests.sessions.Session.request = _original_request
    _original_request = None
    _wrapped_request = None


if __name__ == "sitecustomize":
    install()
