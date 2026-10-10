"""Build a self-contained AgentRange algorithm and benchmark presentation."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

import yaml


ROOT = Path(__file__).resolve().parents[1]
TEMPLATE = Path(__file__).with_name("algorithm_showcase.template.html")
SCENARIOS = ROOT / "integration" / "agentrange_contracts" / "scenario-matrix.yaml"

SCENARIO_COPY = {
    "C1-A": ("框架命令执行", "入口检查", "高危验证请求在转发至 Langflow 前拒绝"),
    "C1-B": ("路径穿越与持久化", "入口检查", "上传路径触及 cron 目录前拒绝"),
    "C2-A": ("跨租户数据读取", "工具检查", "将工具查询目标与 JWT 租户范围比较"),
    "C2-B": ("敏感数据外传", "工具与响应检查", "识别敏感内容及外传目标，在传输前拒绝"),
    "C2-C": ("注入命令执行", "工具检查", "外部内容形成危险工具参数时拒绝"),
    "C2-D": ("凭据读取与外传", "请求与工具检查", "读取或传输凭据前拒绝"),
    "normal": ("正常业务", "全链路检查", "授权请求继续执行并返回业务结果"),
}

GATE_LABELS = {
    "recall_gte_0_95": "攻击检出率 ≥ 95%",
    "precision_gte_0_95": "检测精确率 ≥ 95%",
    "fpr_lt_0_05": "误报率 < 5%",
    "normal_success_rate_1": "正常业务成功率 100%",
    "e2e_p95_lt_1000ms": "端到端 p95 < 1 秒",
    "inspect_p95_lt_1000ms": "检查 p95 < 1 秒",
    "inspect_latency_coverage_1": "检查时延全覆盖",
    "inspect_unavailable_eq_0": "检查不可用为 0",
    "cpu_increment_lte_5pct": "逐容器 CPU 增量 ≤ 5 个百分点",
    "host_gateway_cpu_p95_lte_5pct": "Gateway 宿主 CPU p95 ≤ 5%",
    "combined_defense_cpu_p95_lte_5pct": "联合防护 CPU p95 ≤ 5%",
    "evidence_complete": "实例证据完整",
}


def read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"expected JSON object: {path}")
    return value


def chain_sample(chain: dict[str, Any]) -> dict[str, Any]:
    block_id = chain.get("block_node_id")
    nodes = chain.get("nodes") or []
    selected = [node for index, node in enumerate(nodes) if index < 2 or node.get("id") == block_id]
    return {
        "instance_id": chain.get("instance_id"),
        "blocked": bool(chain.get("blocked")),
        "sequence_type": chain.get("sequence_type"),
        "nodes": [
            {
                "stage": node.get("stage"),
                "asset_id": node.get("asset_id"),
                "http_path": node.get("http_path"),
                "tool_name": node.get("tool_name"),
                "raw_ref": node.get("raw_ref"),
                "blocked": node.get("id") == block_id,
            }
            for node in selected[:4]
        ],
    }


def build_data(report: dict[str, Any], matrix: dict[str, Any]) -> dict[str, Any]:
    benchmark = report.get("benchmark") or {}
    overall = benchmark.get("overall") or {}
    resources = benchmark.get("resources") or {}
    provenance = report.get("benchmark_provenance") or {}
    by_scenario = benchmark.get("by_scenario") or {}
    representative = report.get("chains") or []
    scenarios = []
    for scenario_id, definition in (matrix.get("scenarios") or {}).items():
        name, checkpoint, explanation = SCENARIO_COPY.get(scenario_id, (scenario_id, "检查", ""))
        scored = by_scenario.get(scenario_id) or {}
        sample = next(
            (chain_sample(chain) for chain in representative
             if str(chain.get("instance_id") or "").startswith(scenario_id + "-")),
            None,
        )
        scenarios.append({
            "id": scenario_id,
            "name": name,
            "class": definition.get("class"),
            "target": definition.get("target"),
            "checkpoint": checkpoint,
            "explanation": explanation,
            "danger": definition.get("first_dangerous_action"),
            "counts": scored.get("counts") or {},
            "inspect_p95": (scored.get("inspect_latency_ms") or {}).get("p95"),
            "e2e_p95": (scored.get("latency_ms") or {}).get("p95"),
            "sample": sample,
        })
    baseline = resources.get("baseline") or {}
    host = resources.get("host_gateway") or {}
    combined = resources.get("combined_defense_cpu") or {}
    static_eval = (report.get("static") or {}).get("evaluation") or {}
    return {
        "generated_at": report.get("generated_at"),
        "commit": provenance.get("git_commit"),
        "arena_sha256": provenance.get("arena_sha256"),
        "provenance_verified": bool(provenance.get("comparable_mode_set")),
        "counts": overall.get("counts") or {},
        "metrics": overall.get("metrics") or {},
        "normal": overall.get("normal_business") or {},
        "inspect": overall.get("inspect_latency_ms") or {},
        "e2e": overall.get("latency_ms") or {},
        "availability": overall.get("inspection_availability") or {},
        "cpu": {
            "increment": resources.get("cpu_increment_pct"),
            "baseline_status": baseline.get("status"),
            "throughput_ratio": baseline.get("throughput_ratio"),
            "matched_containers": len(baseline.get("comparable_containers") or []),
            "host_p95": (host.get("cpu_host_pct") or {}).get("p95"),
            "host_status": host.get("status"),
            "combined_p95": (combined.get("cpu_host_pct") or {}).get("p95"),
            "combined_status": combined.get("status"),
        },
        "static": {
            "scope": static_eval.get("scope"),
            "asset": static_eval.get("asset") or {},
            "risk": static_eval.get("risk") or {},
        },
        "runtime": report.get("runtime") or {},
        "gates": [
            {"key": key, "label": GATE_LABELS.get(key, key), "passed": bool(value)}
            for key, value in (benchmark.get("acceptance") or {}).items()
        ],
        "scenarios": scenarios,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    data = build_data(read_json(args.report), yaml.safe_load(SCENARIOS.read_text(encoding="utf-8")) or {})
    payload = json.dumps(data, ensure_ascii=False, separators=(",", ":")).replace("</", "<\\/")
    rendered = TEMPLATE.read_text(encoding="utf-8").replace("__SHOWCASE_DATA__", payload)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(rendered, encoding="utf-8")
    print(json.dumps({"output": str(args.output), "scenarios": len(data["scenarios"]), "gates": len(data["gates"])}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
