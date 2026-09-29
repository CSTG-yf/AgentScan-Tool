import hashlib

from fastapi import FastAPI, Header, HTTPException, Request

from .trajectories import TrajectoryStore

# 全局 store 只保存本轮内存注入的轨迹，回放结束后由 runner 清空。
store = TrajectoryStore()
app = FastAPI(title="opspilot-llm-stub")


@app.get("/health")
def health():
    # 编排层只需要轻量健康检查，避免依赖外部状态。
    return {"status": "ok"}


@app.post("/admin/trajectories")
def replace_trajectories(body: dict):
    trajectories = body.get("trajectories")
    # runner 只接受一次性完整注入，避免增量接口留下旧实例轨迹。
    if not isinstance(trajectories, dict):
        raise HTTPException(status_code=400, detail="trajectories must be an object")

    # 每个实例的轨迹必须是步骤列表，和 Chat Completions 响应结构保持一致。
    for steps in trajectories.values():
        if not isinstance(steps, list):
            raise HTTPException(status_code=400, detail="trajectory steps must be lists")

    store.replace_all(trajectories)
    return {"count": store.count()}


@app.delete("/admin/trajectories")
def clear_trajectories():
    # 回放结束后清空内存轨迹，不把本轮剧本留在模型桩里。
    store.clear()
    return {"count": store.count()}


@app.post("/v1/chat/completions")
async def chat_completions(request: Request, x_instance_id: str | None = Header(default=None)):
    body = await request.json()
    if "prompt" in body:
        raise HTTPException(status_code=400, detail="chat completions require messages, not prompt")
    messages = body.get("messages")
    # LLM stub 只模拟 Chat Completions，入口必须传 messages 数组。
    if not isinstance(messages, list):
        raise HTTPException(status_code=400, detail="messages must be a list")

    # 轨迹步号来自历史 assistant 消息数，调用方不用维护服务端会话。
    instance_id = x_instance_id or "anon"
    index = sum(1 for message in messages if message.get("role") == "assistant")
    step = store.step(instance_id, index)

    # 返回 OpenAI 兼容结构，后续业务网关可以按同一协议替换真实模型。
    model = body.get("model", "opspilot-stub")
    return openai_response(step, model, instance_id, index)


def openai_response(step: dict, model: str, instance_id: str, index: int) -> dict:
    message = {"role": "assistant", "content": step.get("content")}

    # 工具调用存在时 finish_reason 必须标成 tool_calls，方便上层进入工具执行分支。
    if step.get("tool_calls"):
        message["tool_calls"] = step["tool_calls"]
        finish_reason = "tool_calls"
    else:
        finish_reason = "stop"

    # 响应 id 固定由实例和步号生成，同输入重复调用得到完全相同 JSON。
    digest = hashlib.sha256(f"{instance_id}:{index}".encode()).hexdigest()[:16]
    return {
        "id": f"chatcmpl-{digest}",
        "object": "chat.completion",
        "created": 0,
        "model": model,
        "choices": [{"index": 0, "message": message, "finish_reason": finish_reason}],
        "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
    }
