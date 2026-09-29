import json
import os
import pathlib
import uuid

import requests
from fastapi import Depends, FastAPI, Header, HTTPException, Response

from auth.jwt_auth import Identity, issue_token, verify_token
from auth.roles import in_scope
from policy.propagation import trace_headers
from skills.loader import load_skill

# 预置用户代表靶场里的固定身份，登录阶段只根据用户名发放对应 JWT。
USERS = {
    "lwang": Identity("lwang", "support-agent", "support", {"tenant": "acme"}),
    "zsec": Identity("zsec", "sec-analyst", "security", {}),
    "rdev": Identity("rdev", "rd-dev", "rd", {"repo": "opspilot"}),
    "oeng": Identity("oeng", "ops-engineer", "ops", {}),
    "root": Identity("root", "ops-admin", "ops", {}),
}

# 配置默认值保持计划中的弱密钥基线，后续攻击链会围绕它验证风险。
SECRET = os.getenv("JWT_SECRET", "change-me-weak-secret")
TTL = int(os.getenv("JWT_TTL_SECONDS", "3600"))
LLM_BASE = os.getenv("LLM_BASE", "http://llm-stub:8000/v1")
LANGFLOW_BASE = os.getenv("LANGFLOW_BASE", "http://langflow:7860")
LANGFLOW_FLOW_ID = os.getenv("LANGFLOW_FLOW_ID")
MAX_AGENT_STEPS = int(os.getenv("OPSPILOT_MAX_AGENT_STEPS", "8"))
SKILLS_ROOT = pathlib.Path(os.getenv("OPSPILOT_SKILLS_ROOT", "skills"))
MCP_SERVICES = {
    "customer-db": os.getenv("MCP_CUSTOMER_DB", "http://mcp-customer-db:8000/mcp"),
    "shell-runner": os.getenv("MCP_SHELL_RUNNER", "http://mcp-shell-runner:8000/mcp"),
    "notes-sync": os.getenv("MCP_NOTES_SYNC", "http://mcp-notes-sync:8000/mcp"),
    "threat-intel": os.getenv("MCP_THREAT_INTEL", "http://mcp-threat-intel:8000/mcp"),
    "gitlab": os.getenv("MCP_GITLAB", "http://mcp-gitlab:8000/mcp"),
    "monitoring": os.getenv("MCP_MONITORING", "http://mcp-monitoring:8000/mcp"),
    "knowledge": os.getenv("MCP_KNOWLEDGE", "http://mcp-knowledge:8000/mcp"),
    "sandbox-exec": os.getenv("MCP_SANDBOX_EXEC", "http://mcp-sandbox-exec:8000/mcp"),
}
OPENAI_TOOL_ROUTES = {
    "customer_db_query": ("customer-db", "query"),
    "shell_runner_run": ("shell-runner", "run"),
    "shell_runner_read_file": ("shell-runner", "read_file"),
    "notes_sync_sync_note": ("notes-sync", "sync_note"),
    "notes_sync_debug_exec": ("notes-sync", "debug_exec"),
    "threat_intel_lookup": ("threat-intel", "lookup"),
    "gitlab_get_pr": ("gitlab", "get_pr"),
    "monitoring_query_metric": ("monitoring", "query_metric"),
    "knowledge_search": ("knowledge", "search"),
    "sandbox_exec_run_test": ("sandbox-exec", "run_test"),
}
SYSTEM_PROMPT = "你是 OpsPilot，只能根据用户身份、业务上下文和可用工具完成企业协同任务。"
DEFAULT_MODEL = "opspilot-stub"


def prompt_from_body(body: dict) -> str:
    # Agent 对外只暴露自然语言 prompt，旧 input 只作为短期兼容入口。
    if "prompt" in body:
        return str(body["prompt"])
    if "input" in body:
        return json.dumps(body["input"], ensure_ascii=False)
    return ""


def model_from_body(body: dict) -> str:
    # 回放默认使用确定性模型桩，调用方可以显式覆盖 model。
    return str(body.get("model") or DEFAULT_MODEL)


def skill_from_body(body: dict) -> str | None:
    # skill 是 Agent 明确选择的能力包，用于模拟 Skills 的按需加载过程。
    value = body.get("skill")
    return str(value) if value else None


def available_skills() -> list[dict]:
    skills = []
    if not SKILLS_ROOT.exists():
        return skills
    # 只读取 frontmatter 元数据，模拟 Agent 启动时的轻量技能目录。
    for directory in sorted(item for item in SKILLS_ROOT.iterdir() if item.is_dir()):
        skill_file = directory / "SKILL.md"
        if skill_file.exists():
            skill = load_skill(str(directory))
            skills.append({"name": skill["name"], "description": skill.get("description", ""), "allowed_tools": skill.get("allowed_tools", [])})
    return skills


def skill_catalog_message() -> dict:
    skills = available_skills()
    if not skills:
        return {"role": "system", "content": "可用 Skills: 无"}
    lines = ["可用 Skills:"]
    for skill in skills:
        tools = ", ".join(skill["allowed_tools"]) or "none"
        lines.append(f"- {skill['name']}: {skill['description']}；allowed-tools={tools}")
    return {"role": "system", "content": "\n".join(lines)}


def loaded_skill_message(name: str) -> dict:
    skill_dir = SKILLS_ROOT / name
    if not (skill_dir / "SKILL.md").exists():
        raise HTTPException(status_code=400, detail="unknown skill")
    # 被触发的 Skill 正文会进入上下文，投毒指令也会随正文暴露给模型。
    skill = load_skill(str(skill_dir))
    content = f"已加载 Skill: {skill['name']}\n来源: {skill_dir / 'SKILL.md'}\n{skill['body']}"
    return {"role": "system", "content": content}


def agent_messages(prompt: str, skill_name: str | None = None) -> list[dict]:
    # Agent 每轮都带轻量目录，便于从 LLM 请求报文里观察技能发现阶段。
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        skill_catalog_message(),
    ]
    if skill_name:
        messages.append(loaded_skill_message(skill_name))
    messages.append({"role": "user", "content": prompt})
    return messages


def mcp_route_for_tool(openai_name: str) -> tuple[str, str] | None:
    # OpenAI function name 在 Agent 内部映射回 MCP 服务和工具名。
    return OPENAI_TOOL_ROUTES.get(openai_name)


def openai_tool_specs() -> list[dict]:
    # LLM 只看到 OpenAI 合法工具名，Agent 再把名称映射回内部 MCP。
    return [
        {
            "type": "function",
            "function": {
                "name": "customer_db_query",
                "description": "按租户查询客户记录。",
                "parameters": {"type": "object", "properties": {"tenant": {"type": "string"}}, "required": ["tenant"]},
            },
        },
        {
            "type": "function",
            "function": {
                "name": "shell_runner_run",
                "description": "在受管运维主机上执行 shell 命令。",
                "parameters": {"type": "object", "properties": {"cmd": {"type": "string"}}, "required": ["cmd"]},
            },
        },
        {
            "type": "function",
            "function": {
                "name": "shell_runner_read_file",
                "description": "读取受管主机上的文本文件。",
                "parameters": {"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]},
            },
        },
        {
            "type": "function",
            "function": {
                "name": "notes_sync_sync_note",
                "description": "同步一条团队笔记。",
                "parameters": {"type": "object", "properties": {"text": {"type": "string"}}, "required": ["text"]},
            },
        },
        {
            "type": "function",
            "function": {
                "name": "notes_sync_debug_exec",
                "description": "内部调试命令。",
                "parameters": {"type": "object", "properties": {"cmd": {"type": "string"}}, "required": ["cmd"]},
            },
        },
        {
            "type": "function",
            "function": {
                "name": "threat_intel_lookup",
                "description": "查询公开漏洞情报。",
                "parameters": {"type": "object", "properties": {"cve": {"type": "string"}}, "required": ["cve"]},
            },
        },
        {
            "type": "function",
            "function": {
                "name": "gitlab_get_pr",
                "description": "获取指定 PR 的标题与 diff。",
                "parameters": {"type": "object", "properties": {"pr_id": {"type": "integer"}}, "required": ["pr_id"]},
            },
        },
        {
            "type": "function",
            "function": {
                "name": "monitoring_query_metric",
                "description": "查询监控指标当前值。",
                "parameters": {"type": "object", "properties": {"name": {"type": "string"}}, "required": ["name"]},
            },
        },
        {
            "type": "function",
            "function": {
                "name": "knowledge_search",
                "description": "检索内部知识库文档片段。",
                "parameters": {"type": "object", "properties": {"q": {"type": "string"}}, "required": ["q"]},
            },
        },
        {
            "type": "function",
            "function": {
                "name": "sandbox_exec_run_test",
                "description": "在隔离沙箱中运行白名单测试套件。",
                "parameters": {"type": "object", "properties": {"cmd": {"type": "string"}}, "required": ["cmd"]},
            },
        },
    ]


app = FastAPI(title="opspilot-app")


@app.get("/health")
def health():
    # 编排健康检查不触发数据库和模型调用，降低启动顺序干扰。
    return {"status": "ok"}


@app.post("/login")
def login(body: dict):
    # 靶场简化登录流程，未知用户直接拒绝，不引入密码存储。
    identity = USERS.get(body.get("username"))
    if identity is None:
        raise HTTPException(status_code=401, detail="unknown user")

    # token_type 固定为 bearer，便于客户端按标准 Authorization 头调用。
    return {"access_token": issue_token(identity, SECRET, TTL), "token_type": "bearer"}


def current_identity(authorization: str | None = Header(default=None)) -> Identity:
    # 所有受保护端点都要求 Bearer token，缺失时返回 401。
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="missing bearer token")

    # JWT 校验失败统一映射成 401，不向调用方泄露签名或过期细节。
    try:
        token = authorization.split(" ", 1)[1]
        return verify_token(token, SECRET)
    except Exception as exc:
        raise HTTPException(status_code=401, detail="invalid token") from exc


@app.get("/me")
def me(identity: Identity = Depends(current_identity)):
    # /me 返回 JWT 中的身份视图，用于验证登录和 scope 是否一致。
    return {
        "sub": identity.sub,
        "role": identity.role,
        "team": identity.team,
        "scope": identity.scope,
    }


@app.get("/support/customers")
def list_customers(tenant: str, identity: Identity = Depends(current_identity)):
    # 正常业务路径先按租户 scope 拦截，工具层绕过会在后续计划中覆盖。
    if not in_scope(identity, resource_tenant=tenant):
        raise HTTPException(status_code=403, detail="cross-tenant access denied")

    # 这里只返回空客户列表，数据读取由 customer-db 和后续工具链负责。
    return {"tenant": tenant, "customers": []}


@app.post("/run")
def run_agent(
    body: dict,
    response: Response,
    x_instance_id: str | None = Header(default=None),
    x_trace_id: str | None = Header(default=None),
    identity: Identity = Depends(current_identity),
):
    trace_id = x_trace_id or str(uuid.uuid4())
    response.headers["X-Trace-Id"] = trace_id

    # 部署接入 Langflow 后，保留同一个 /run 入口和实例 id 透传。
    if LANGFLOW_FLOW_ID:
        payload = {
            "input_value": body.get("input", {}),
            "output_type": "chat",
            "input_type": "chat",
        }
        headers = {"X-Instance-Id": x_instance_id or "manual", "X-Acting-User": identity.sub}
        response = requests.post(
            f"{LANGFLOW_BASE}/api/v1/run/{LANGFLOW_FLOW_ID}",
            headers=headers,
            json=payload,
            timeout=30,
        )
        return response.json()

    model = model_from_body(body)
    prompt = prompt_from_body(body)
    skill_name = skill_from_body(body)
    messages = agent_messages(prompt, skill_name)
    headers = trace_headers(trace_id)
    headers["X-Instance-Id"] = x_instance_id or "manual"

    # 离线路径模拟最小 agent executor，返回体保持 ChatCompletion 形态。
    llm_response = run_stub_agent(messages, headers, model)
    return llm_response


def run_stub_agent(messages: list[dict], headers: dict, model: str = DEFAULT_MODEL) -> dict:
    tool_results = []
    llm_response = {}
    for _ in range(MAX_AGENT_STEPS):
        payload = {"model": model, "messages": messages, "tools": openai_tool_specs(), "tool_choice": "auto", "temperature": 0}
        # 实例 id 每轮都透传给 llm-stub；assistant 轮次会推动固定轨迹进入下一步。
        response = requests.post(f"{LLM_BASE}/chat/completions", headers=headers, json=payload, timeout=10)
        llm_response = response.json()
        message = first_message(llm_response)
        messages.append(message)

        # 没有 tool_calls 说明模型桩已经到 stop 回合，回放链路结束。
        if not message.get("tool_calls"):
            break
        round_results = run_tool_calls(llm_response, headers)
        tool_results.extend(round_results)
        append_tool_messages(messages, round_results)
    return llm_response


def first_message(llm_response: dict) -> dict:
    choices = llm_response.get("choices", [])
    if not choices:
        return {"role": "assistant", "content": ""}
    return choices[0].get("message", {"role": "assistant", "content": ""})


def append_tool_messages(messages: list[dict], tool_results: list[dict]) -> None:
    for item in tool_results:
        # 工具结果回灌到 messages，保留真实 agent 循环的上下文形态。
        messages.append({
            "role": "tool",
            "tool_call_id": item.get("tool_call_id", item["tool"]),
            "content": json.dumps(item.get("result"), ensure_ascii=False),
        })


def run_tool_calls(llm_response: dict, headers: dict) -> list[dict]:
    choices = llm_response.get("choices", [])
    if not choices:
        return []
    message = choices[0].get("message", {})
    results = []
    # 这里只执行当前回合的工具调用；多轮推进由回放语料用 assistant 轮次控制。
    for call in message.get("tool_calls", []):
        function = call.get("function", {})
        name = function.get("name", "")
        route = mcp_route_for_tool(name)
        if route is None:
            results.append({"tool": name, "error": "unknown MCP tool"})
            continue
        server, tool = route
        endpoint = MCP_SERVICES.get(server)
        if not endpoint:
            results.append({"tool": name, "error": "unknown MCP server"})
            continue
        args = json.loads(function.get("arguments") or "{}")
        results.append({"tool": name, "tool_call_id": call.get("id"), "result": call_mcp(endpoint, tool, args, headers)})
    return results


def call_mcp(endpoint: str, tool: str, args: dict, headers: dict | None = None) -> dict:
    # MCP 使用 JSON-RPC 2.0 HTTP 传输，Trace ID 只用于跨服务取证。
    response = requests.post(
        endpoint,
        headers=headers or {},
        json={"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": tool, "arguments": args}},
        timeout=10,
    )
    data = response.json()
    return data.get("result", data)
