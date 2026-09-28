import json
import hashlib
import os
import pathlib
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
        # Cat-1 replay routing uses a generic operation name, never a
        # scenario identifier.  The detector receives only the resulting
        # Langflow HTTP request.
        if event_input.get("operation") in {"code_validation", "file_upload"}:
            exploit = "C1-A" if event_input["operation"] == "code_validation" else "C1-B"
            actions.append({"instance_id": event["instance_id"], "target": "langflow", "exploit": exploit, "cmd": event_input["cmd"]})
        elif event_input.get("source"):
            # Cat-2 公开事件走自然语言 prompt 入口，source 只表示外部输入来源。
            body = {"model": "opspilot-stub", "prompt": event_input["prompt"]}
            if event_input.get("skill"):
                body["skill"] = event_input["skill"]
            actions.append(
                {
                    "instance_id": event["instance_id"],
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


def _observation(action: dict, *, status: int | None, body: bytes = b"", started: float, error: str | None = None) -> dict:
    blocked = status == 403
    return {
        "instance_id": action["instance_id"],
        "mode": os.getenv("AGENTRANGE_MODE", "action"),
        "request_id": action["instance_id"],
        "status": status,
        "valid": error is None,
        "timeout": isinstance(error, str) and "timeout" in error.lower(),
        "decision": "block" if blocked else ("allow" if error is None else "unknown"),
        "e2e_latency_ms": round((time.perf_counter() - started) * 1000, 3),
        "business_success": bool(status is not None and 200 <= status < 300 and not blocked),
        # Side-effect probes are filled by the benchmark harness after the
        # request.  A successful HTTP response alone is not proof of safety.
        "side_effect_reached": None,
        "side_effect_probe_refs": [],
        "response_body_sha256": hashlib.sha256(body).hexdigest() if body else None,
        "error": error,
    }


def replay_events(events: list[dict], only: str | None = None) -> list[dict]:
    if only and only != "all":
        # New public corpora intentionally omit scenario labels.  Filtering
        # is therefore available only for legacy corpora that explicitly
        # carry the field; generated runs filter before sanitization.
        events = [event for event in events if event.get("scenario") == only]
    # 网络执行只在人工 make replay 时发生，离线测试验证 plan_actions。
    with httpx.Client(timeout=15) as client:
        tokens = {}
        langflow_token = None
        observations = []
        for action in plan_actions(events):
            if action["target"] == "langflow":
                # Cat-1 模拟浏览器自动登录后的真实访问形态，token 在同一次回放中复用。
                langflow_token = langflow_token or fetch_langflow_token(client)
                observations.append(fire_cat1(client, action, langflow_token))
            else:
                observations.append(fire_opspilot(client, action, tokens))
        return observations


def select_events(events: list, only: str | None = None) -> list:
    # 单场景回放时只保留本次要执行的事件，管理轨迹也不混入其他场景。
    if only and only != "all":
        return [event for event in events if event.scenario == only]
    return events


def replay_generated(
    only: str | None = None,
    seed: int = 1337,
    total: int = 5200,
    malicious_target: int = 80,
    output_dir: str | None = None,
):
    output_dir = output_dir or os.getenv("AGENTRANGE_RUN_DIR")
    generated = generate(seed, total, malicious_target)
    selected = select_events(generated, only)
    public_events = [public_record(event) for event in selected]

    # trajectories 只进入 llm-stub 内存，finally 保证回放失败时也清理。
    inject_trajectories(trajectory_map(selected))
    try:
        observations = replay_events(public_events, only=None)
    finally:
        clear_trajectories()
    if output_dir:
        output = pathlib.Path(output_dir)
        output.mkdir(parents=True, exist_ok=True)
        with (output / "observations.jsonl").open("w", encoding="utf-8", newline="\n") as handle:
            for row in observations:
                handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
    return observations


def replay(corpus_path: str, only: str | None = None):
    events = [json.loads(line) for line in pathlib.Path(corpus_path).read_text(encoding="utf-8").splitlines()]
    replay_events(events, only=only)


def fire_cat1(client: httpx.Client, action: dict, langflow_token: str):
    from cat1.exploit_0770 import make_payload
    from cat1.exploit_5027 import make_upload

    # Cat-1 直接打 Langflow 漏洞端点，但当前镜像需要 auto_login 换来的 bearer token。
    headers = {"Authorization": f"Bearer {langflow_token}"}
    started = time.perf_counter()
    try:
        if action["exploit"] == "C1-A":
            req = make_payload(action["cmd"])
            response = client.post(f"{LANGFLOW}{req['path']}", headers=headers, json=req["json"])
        else:
            upload = make_upload(f"/etc/cron.d/{action['instance_id']}", "* * * * * root id")
            # Langflow 会按上传文件名做去重；路径穿越文件名需要 append 模式才能稳定回放多条样本。
            response = client.post(f"{LANGFLOW}{upload['path']}", headers=headers, params={"append": "true"}, files={"file": (upload["filename"], upload["content"])})
        return _observation(action, status=response.status_code, body=response.content, started=started)
    except httpx.HTTPError as exc:
        return _observation(action, status=getattr(getattr(exc, "response", None), "status_code", None), started=started, error=str(exc))


def fire_opspilot(client: httpx.Client, action: dict, tokens: dict):
    username = action["username"]
    # 同一用户 token 缓存复用，避免回放里产生不必要登录噪声。
    tokens.setdefault(username, login_token(client, username))
    headers = dict(action.get("headers", {}))
    headers["Authorization"] = f"Bearer {tokens[username]}"
    body = action["body"]
    started = time.perf_counter()
    try:
        response = client.post(f"{OPSPILOT}/run", headers=headers, json=body)
        return _observation(action, status=response.status_code, body=response.content, started=started)
    except httpx.HTTPError as exc:
        return _observation(action, status=getattr(getattr(exc, "response", None), "status_code", None), started=started, error=str(exc))


if __name__ == "__main__":
    import sys

    replay_generated(only=sys.argv[1] if len(sys.argv) > 1 else None)
