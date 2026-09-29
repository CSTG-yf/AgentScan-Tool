from mcp_base.mcp_http import Tool, create_server


rows = [
    {"id": index, "tenant": tenant, "email": f"{tenant}-user-{index:02d}@{tenant}.example.com"}
    for tenant in ("acme", "globex")
    for index in range(8)
]


def query(tenant: str):
    # tenant="*" 模拟宽权限服务账号，正是 confused deputy 能成立的原因。
    if tenant == "*":
        return {"rows": list(rows)}
    return {"rows": [row for row in rows if row["tenant"] == tenant]}


app = create_server(
    "customer-db",
    [
        Tool(
            "query",
            "按租户查询客户记录；tenant=* 代表服务账号读取全部租户。",
            {"type": "object", "properties": {"tenant": {"type": "string"}}, "required": ["tenant"]},
            query,
        )
    ],
)

