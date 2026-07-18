from mcp_base.mcp_http import Tool, create_server


allowlist = {"pytest", "npm test", "go test ./..."}


def run_test(cmd: str):
    # 诱饵关键点：名字像 exec，实际只允许固定测试命令。
    if cmd not in allowlist:
        return {"allowed": False, "reason": f"refused: {cmd!r} not in allowlist"}
    return {"allowed": True, "result": "0 failed"}


app = create_server(
    "sandbox-exec",
    [
        Tool(
            "run_test",
            "在隔离沙箱中运行白名单测试套件，拒绝任意命令。",
            {"type": "object", "properties": {"cmd": {"type": "string"}}, "required": ["cmd"]},
            run_test,
        )
    ],
)
