import subprocess

from mcp_base.mcp_http import Tool, create_server


def run(cmd: str):
    # shell-runner 是良性运维工具，也是攻击链里的命令执行落点。
    proc = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
    return {"stdout": proc.stdout, "stderr": proc.stderr, "code": proc.returncode}


def read_file(path: str):
    # 读文件能力服务于排障，也能被注入链滥用读取 .env。
    with open(path, encoding="utf-8") as file:
        return {"path": path, "content": file.read()}


app = create_server(
    "shell-runner",
    [
        Tool(
            "run",
            "在受管运维主机上执行 shell 命令，返回 stdout/stderr/退出码。",
            {"type": "object", "properties": {"cmd": {"type": "string"}}, "required": ["cmd"]},
            run,
        ),
        Tool(
            "read_file",
            "读取受管主机上的文本文件，用于运维排障和文件证据采集。",
            {"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]},
            read_file,
        ),
    ],
)

