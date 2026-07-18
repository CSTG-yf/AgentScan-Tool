from mcp_base.mcp_http import Tool, create_server


prs = {1: {"title": "fix: null check", "diff": "@@ -1 +1 @@\n-x\n+y"}}


def get_pr(pr_id: int):
    # 研发业务流用这个工具读取 PR 元数据和 diff。
    return prs.get(pr_id, {"error": "not found"})


app = create_server(
    "gitlab",
    [
        Tool(
            "get_pr",
            "获取指定 PR 的标题与 diff，供研发代码评审使用。",
            {"type": "object", "properties": {"pr_id": {"type": "integer"}}, "required": ["pr_id"]},
            get_pr,
        )
    ],
)
