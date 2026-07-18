"""DefenseClaw-backed ingress guard for the vulnerable Langflow component."""

from __future__ import annotations

import json
import os
from typing import Any

import httpx
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse


app = FastAPI(title="agent-range-langflow-guard")
UPSTREAM_BASE = os.getenv("UPSTREAM_BASE", "http://langflow:7860").rstrip("/")
DEFENSECLAW_API_BASE = os.getenv("DEFENSECLAW_API_BASE", "").rstrip("/")
DEFENSECLAW_API_TOKEN = os.getenv("DEFENSECLAW_API_TOKEN", "")
FAIL_MODE = os.getenv("DEFENSECLAW_FAIL_MODE", "open").lower()
TIMEOUT = float(os.getenv("DEFENSECLAW_TIMEOUT_SECONDS", "0.25"))


async def inspect_ingress(request: Request, body: bytes) -> dict[str, Any]:
    if not DEFENSECLAW_API_BASE:
        return {"action": "allow", "mode": "disabled"}
    headers = {"Content-Type": "application/json"}
    if DEFENSECLAW_API_TOKEN:
        headers["Authorization"] = f"Bearer {DEFENSECLAW_API_TOKEN}"
    payload = {
        "tool": "langflow_http",
        "args": {
            "method": request.method,
            "path": request.url.path,
            "query": request.url.query,
            # Multipart filenames and exploit bodies remain visible to the
            # rule engine while invalid bytes are safely replaced.
            "body": body.decode("utf-8", errors="replace"),
        },
        "direction": "tool_call",
        "session_id": request.headers.get("x-instance-id", "langflow-http"),
        "connector": "opspilot",
        "mcp_server_name": "langflow",
    }
    try:
        async with httpx.AsyncClient(timeout=TIMEOUT) as client:
            response = await client.post(
                f"{DEFENSECLAW_API_BASE}/api/v1/inspect/tool",
                headers=headers,
                content=json.dumps(payload, ensure_ascii=False).encode(),
            )
            response.raise_for_status()
            return response.json()
    except (httpx.HTTPError, ValueError) as exc:
        action = "block" if FAIL_MODE == "closed" else "allow"
        return {"action": action, "severity": "HIGH", "reason": f"inspection unavailable: {type(exc).__name__}"}


@app.get("/guard/health")
def health():
    return {"status": "ok", "protected": bool(DEFENSECLAW_API_BASE), "upstream": UPSTREAM_BASE}


@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"])
async def proxy(path: str, request: Request):
    body = await request.body()
    verdict = await inspect_ingress(request, body)
    if verdict.get("action") == "block":
        return JSONResponse(
            status_code=403,
            content={"code": "DEFENSECLAW_BLOCKED", "stage": "langflow-ingress", "verdict": verdict},
        )

    forward_headers = {
        key: value
        for key, value in request.headers.items()
        if key.lower() not in {"host", "content-length", "connection", "transfer-encoding"}
    }
    url = f"{UPSTREAM_BASE}/{path}"
    if request.url.query:
        url += f"?{request.url.query}"
    async with httpx.AsyncClient(timeout=30) as client:
        upstream = await client.request(request.method, url, headers=forward_headers, content=body)
    response_headers = {
        key: value
        for key, value in upstream.headers.items()
        if key.lower() not in {"content-length", "connection", "transfer-encoding", "content-encoding"}
    }
    return Response(upstream.content, status_code=upstream.status_code, headers=response_headers)
