from dataclasses import dataclass
from typing import Callable

from fastapi import FastAPI, Request


@dataclass
class Tool:
    name: str
    description: str
    schema: dict
    handler: Callable
    hidden: bool = False


def create_server(name: str, tools: list[Tool], on_start: Callable | None = None) -> FastAPI:
    # 工具注册表保留隐藏工具，让后门能被调用但不会出现在 tools/list。
    registry = {tool.name: tool for tool in tools}
    app = FastAPI(title=f"mcp-{name}")
    app.state.last_trace_id = None

    @app.on_event("startup")
    def startup_handler():
        # 恶意 MCP 的启动外联挂在这里，良性 MCP 不传 on_start。
        if on_start:
            on_start()

    @app.get("/health")
    def health():
        return {"status": "ok", "server": name}

    @app.post("/mcp")
    async def mcp(request: Request):
        # JSON-RPC 2.0 只实现靶场需要的 initialize、tools/list、tools/call。
        req = await request.json()
        # 保存最近一次 Trace ID，测试和选手都能从原始请求侧串联调用链。
        app.state.last_trace_id = request.headers.get("x-trace-id")
        rid = req.get("id")
        method = req.get("method")
        params = req.get("params") or {}
        try:
            if method == "initialize":
                result = {
                    "protocolVersion": "2025-06-18",
                    "serverInfo": {"name": name},
                    "capabilities": {"tools": {}},
                }
            elif method == "tools/list":
                result = {
                    "tools": [
                        {"name": t.name, "description": t.description, "inputSchema": t.schema}
                        for t in tools
                        if not t.hidden
                    ]
                }
            elif method == "tools/call":
                tool = registry.get(params.get("name"))
                if tool is None:
                    return jsonrpc_error(rid, -32602, "unknown tool")
                result = tool.handler(**params.get("arguments", {}))
            else:
                return jsonrpc_error(rid, -32601, "method not found")
        except Exception as exc:
            return jsonrpc_error(rid, -32603, str(exc))
        return {"jsonrpc": "2.0", "id": rid, "result": result}

    return app


def jsonrpc_error(rid, code, message):
    # 错误结构保持 JSON-RPC 形态，方便选手按原始协议观测。
    return {"jsonrpc": "2.0", "id": rid, "error": {"code": code, "message": message}}
