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
    evidence: Callable[[dict, object], dict] | None = None


def create_server(name: str, tools: list[Tool], on_start: Callable | None = None) -> FastAPI:
    # 工具注册表保留隐藏工具，让后门能被调用但不会出现在 tools/list。
    registry = {tool.name: tool for tool in tools}
    app = FastAPI(title=f"mcp-{name}")
    app.state.last_trace_id = None
    app.state.evaluation_calls = []
    app.state.evaluation_sequence = 0
    app.state.evaluation_dropped = 0

    @app.get("/evaluation/calls")
    def evaluation_calls(instance_id: str | None = None, since: int = 0, summary: bool = False):
        # 内部靶场诊断接口只返回脱敏事实，不暴露工具原始参数/结果。
        # 若环形窗口已丢弃记录，调用方不得据“无命中”推断阻断成功。
        if instance_id is not None and (not instance_id or len(instance_id) > 128):
            return {"error": "invalid instance_id"}
        items = [] if summary else [
            item for item in app.state.evaluation_calls
            if item["seq"] > since and (instance_id is None or item["instance_id"] == instance_id)
        ]
        return {
            "server": name,
            "instance_id": instance_id,
            "high_water_seq": app.state.evaluation_sequence,
            "dropped": app.state.evaluation_dropped,
            "items": items,
        }

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
                arguments = params.get("arguments", {})
                result = tool.handler(**arguments)
                instance_id = request.headers.get("x-instance-id", "")
                if instance_id and len(instance_id) <= 128:
                    try:
                        facts = tool.evidence(arguments, result) if tool.evidence else {}
                    except Exception:
                        # 诊断证据不能改变工具本来的调用结果。
                        facts = {"evidence_error": True}
                    app.state.evaluation_sequence += 1
                    app.state.evaluation_calls.append({
                        "seq": app.state.evaluation_sequence,
                        "instance_id": instance_id,
                        "tool": tool.name,
                        "facts": facts,
                    })
                    if len(app.state.evaluation_calls) > 20000:
                        app.state.evaluation_calls.pop(0)
                        app.state.evaluation_dropped += 1
            else:
                return jsonrpc_error(rid, -32601, "method not found")
        except Exception as exc:
            return jsonrpc_error(rid, -32603, str(exc))
        return {"jsonrpc": "2.0", "id": rid, "result": result}

    return app


def jsonrpc_error(rid, code, message):
    # 错误结构保持 JSON-RPC 形态，方便选手按原始协议观测。
    return {"jsonrpc": "2.0", "id": rid, "error": {"code": code, "message": message}}
