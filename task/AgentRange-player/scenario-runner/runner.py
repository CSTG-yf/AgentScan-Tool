import json
import os
import pathlib
import statistics
import sys
import time

import httpx

# 直接执行 runner.py 时，补上相邻模块路径以调用 Cat-1 和内存生成器。
root = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(root / "attack"))
sys.path.insert(0, str(root / "corpus-generator"))

from generate import generate, public_record, trajectory_map

OPSPILOT = os.getenv("OPSPILOT_BASE", "http://localhost:8100")
LANGFLOW = os.getenv("LANGFLOW_BASE", "http://localhost:7860")
LLM_STUB = os.getenv("LLM_STUB_BASE", "http://localhost:8000")


def plan_actions(events: list[dict]) -> list[dict]:
    actions = []
    # 回放动作严格按 t 排序，保证同一 corpus 每次产生相同顺序。
    for event in sorted(events, key=lambda item: item["t"]):
        event_input = event["input"]
        # Cat-1 公开事件保留利用参数，runner 由 exploit 字段识别 Langflow 路径。
        if event_input.get("exploit"):
            actions.append({"instance_id": event["instance_id"], "scenario": event["scenario"], "target": "langflow", "exploit": event["input"]["exploit"], "cmd": event["input"]["cmd"]})
        elif event_input.get("source"):
            # Cat-2 公开事件走自然语言 prompt 入口，source 只表示外部输入来源。
            body = {"model": "opspilot-stub", "prompt": event_input["prompt"]}
            if event_input.get("skill"):
                body["skill"] = event_input["skill"]
            actions.append(
                {
                    "instance_id": event["instance_id"],
                    "scenario": event["scenario"],
                    "target": "opspilot-app",
                    "headers": {"X-Instance-Id": event["instance_id"], "X-Trace-Id": event["instance_id"]},
                    "username": event["actor"]["sub"],
                    "body": body,
                }
            )
        else:
            # 普通业务流量只需要 prompt、actor 和实例头即可完成回放。
            actions.append(
                {
                    "instance_id": event["instance_id"],
                    "scenario": event["scenario"],
                    "target": "opspilot-app",
                    "headers": {"X-Instance-Id": event["instance_id"], "X-Trace-Id": event["instance_id"]},
                    "username": event["actor"]["sub"],
                    "body": {"model": "opspilot-stub", "prompt": event_input["prompt"]},
                }
            )
    return actions


def login_token(client: httpx.Client, username: str) -> str:
    # runner 复用 OpsPilot 登录接口，让回放流量带真实 JWT。
    response = client.post(f"{OPSPILOT}/login", json={"username": username})
    response.raise_for_status()
    return response.json()["access_token"]


def fetch_langflow_token(client: httpx.Client) -> str:
    # Langflow AUTO_LOGIN 是先换取前端会话 token，再由后续 API 带 bearer 访问。
    response = client.get(f"{LANGFLOW}/api/v1/auto_login")
    response.raise_for_status()
    return response.json()["access_token"]


def inject_trajectories(trajectories: dict[str, list[dict]]) -> None:
    # 回放前把本轮模型轨迹注入 llm-stub 内存，不再依赖 corpus/trajectories.json。
    response = httpx.post(f"{LLM_STUB}/admin/trajectories", json={"trajectories": trajectories}, timeout=15)
    response.raise_for_status()


def clear_trajectories() -> None:
    # 回放结束后清空 llm-stub 内存，避免剧本轨迹在服务中残留。
    response = httpx.delete(f"{LLM_STUB}/admin/trajectories", timeout=15)
    response.raise_for_status()


def is_attack_scenario(scenario: str) -> bool:
    return scenario.startswith(("C1-", "C2-", "M-"))


def percentile(values: list[float], quantile: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, round((len(ordered) - 1) * quantile)))
    return ordered[index]


def summarize_records(records: list[dict]) -> dict:
    tp = sum(1 for item in records if item["attack"] and item["blocked"])
    fn = sum(1 for item in records if item["attack"] and not item["blocked"])
    fp = sum(1 for item in records if not item["attack"] and item["blocked"])
    tn = sum(1 for item in records if not item["attack"] and not item["blocked"])
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    fpr = fp / (fp + tn) if fp + tn else 0.0
    fnr = fn / (fn + tp) if fn + tp else 0.0
    latencies = [item["latency_ms"] for item in records]
    by_scenario = {}
    for item in records:
        bucket = by_scenario.setdefault(item["scenario"], {"total": 0, "blocked": 0, "errors": 0})
        bucket["total"] += 1
        bucket["blocked"] += int(item["blocked"])
        bucket["errors"] += int(bool(item.get("error")))
    return {
        "counts": {"total": len(records), "tp": tp, "fp": fp, "tn": tn, "fn": fn},
        "metrics": {
            "precision": round(precision, 6),
            "recall": round(recall, 6),
            "fpr": round(fpr, 6),
            "fnr": round(fnr, 6),
            "latency_ms": {
                "mean": round(statistics.fmean(latencies), 3) if latencies else 0.0,
                "p50": round(percentile(latencies, 0.50), 3),
                "p95": round(percentile(latencies, 0.95), 3),
                "p99": round(percentile(latencies, 0.99), 3),
            },
        },
        "by_scenario": by_scenario,
        "records": records,
    }


def replay_events(events: list[dict], only: str | None = None) -> dict:
    if only and only != "all":
        events = [event for event in events if event["scenario"] == only]
    # 网络执行只在人工 make replay 时发生，离线测试验证 plan_actions。
    with httpx.Client(timeout=15) as client:
        tokens = {}
        langflow_token = None
        records = []
        for action in plan_actions(events):
            started = time.perf_counter()
            response = None
            error = ""
            try:
                if action["target"] == "langflow":
                    # Cat-1 模拟浏览器自动登录后的真实访问形态，token 在同一次回放中复用。
                    langflow_token = langflow_token or fetch_langflow_token(client)
                    response = fire_cat1(client, action, langflow_token)
                else:
                    response = fire_opspilot(client, action, tokens)
                if response.status_code != 403:
                    response.raise_for_status()
            except Exception as exc:
                error = f"{type(exc).__name__}: {exc}"
            latency_ms = (time.perf_counter() - started) * 1000
            blocked = response is not None and response.status_code == 403
            records.append(
                {
                    "instance_id": action["instance_id"],
                    "scenario": action["scenario"],
                    "target": action["target"],
                    "attack": is_attack_scenario(action["scenario"]),
                    "blocked": blocked,
                    "status_code": response.status_code if response is not None else 0,
                    "latency_ms": round(latency_ms, 3),
                    "error": error,
                }
            )
        return summarize_records(records)


def select_events(events: list, only: str | None = None) -> list:
    # 单场景回放时只保留本次要执行的事件，管理轨迹也不混入其他场景。
    if only and only != "all":
        return [event for event in events if event.scenario == only]
    return events


def replay_generated(only: str | None = None, seed: int = 1337, total: int = 5200, malicious_target: int = 80) -> dict:
    generated = generate(seed, total, malicious_target)
    selected = select_events(generated, only)
    public_events = [public_record(event) for event in selected]

    # trajectories 只进入 llm-stub 内存，finally 保证回放失败时也清理。
    inject_trajectories(trajectory_map(selected))
    try:
        return replay_events(public_events, only=None)
    finally:
        clear_trajectories()


def replay(corpus_path: str, only: str | None = None):
    events = [json.loads(line) for line in pathlib.Path(corpus_path).read_text(encoding="utf-8").splitlines()]
    return replay_events(events, only=only)


def fire_cat1(client: httpx.Client, action: dict, langflow_token: str):
    from cat1.exploit_0770 import make_payload
    from cat1.exploit_5027 import make_upload

    # Cat-1 直接打 Langflow 漏洞端点，但当前镜像需要 auto_login 换来的 bearer token。
    headers = {"Authorization": f"Bearer {langflow_token}"}
    if action["exploit"] == "C1-A":
        req = make_payload(action["cmd"])
        response = client.post(f"{LANGFLOW}{req['path']}", headers=headers, json=req["json"])
    else:
        upload = make_upload(f"/etc/cron.d/{action['instance_id']}", "* * * * * root id")
        # Langflow 会按上传文件名做去重；路径穿越文件名需要 append 模式才能稳定回放多条样本。
        response = client.post(f"{LANGFLOW}{upload['path']}", headers=headers, params={"append": "true"}, files={"file": (upload["filename"], upload["content"])})
    return response


def fire_opspilot(client: httpx.Client, action: dict, tokens: dict):
    username = action["username"]
    # 同一用户 token 缓存复用，避免回放里产生不必要登录噪声。
    tokens.setdefault(username, login_token(client, username))
    headers = dict(action.get("headers", {}))
    headers["Authorization"] = f"Bearer {tokens[username]}"
    body = action["body"]
    response = client.post(f"{OPSPILOT}/run", headers=headers, json=body)
    return response


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Replay AgentRange traffic and calculate instance-level metrics")
    parser.add_argument("scenario", nargs="?", default=None, help="optional scenario such as C2-D")
    parser.add_argument("--report", help="write the full JSON report to this path")
    parser.add_argument("--total", type=int, default=5200)
    parser.add_argument("--malicious-target", type=int, default=80)
    args = parser.parse_args()
    report = replay_generated(only=args.scenario, total=args.total, malicious_target=args.malicious_target)
    summary = {key: value for key, value in report.items() if key != "records"}
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    if args.report:
        report_path = pathlib.Path(args.report)
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
