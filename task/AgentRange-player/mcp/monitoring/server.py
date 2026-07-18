from mcp_base.mcp_http import Tool, create_server


def query_metric(name: str):
    # 运维基线事件读取稳定指标，给良性流量提供背景噪声。
    return {"metric": name, "value": 0.42}


app = create_server(
    "monitoring",
    [
        Tool(
            "query_metric",
            "查询监控指标当前值，用于告警研判。",
            {"type": "object", "properties": {"name": {"type": "string"}}, "required": ["name"]},
            query_metric,
        )
    ],
)
