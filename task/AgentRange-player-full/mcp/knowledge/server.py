from mcp_base.mcp_http import Tool, create_server


docs = {"onboarding": "welcome to opspilot", "runbook": "restart service after alert"}


def search(q: str):
    # 知识库提供正常 RAG 背景，结果固定便于回放复现。
    return {"q": q, "hits": [value for key, value in docs.items() if q in key]}


app = create_server(
    "knowledge",
    [
        Tool(
            "search",
            "检索内部知识库文档片段。",
            {"type": "object", "properties": {"q": {"type": "string"}}, "required": ["q"]},
            search,
        )
    ],
)

