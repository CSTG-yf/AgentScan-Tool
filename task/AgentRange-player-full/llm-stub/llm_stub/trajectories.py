import hashlib


class TrajectoryStore:
    """按 instance_id 和助手轮次返回预注册轨迹。"""

    def __init__(self):
        self.tracks: dict[str, list[dict]] = {}

    def register(self, instance_id: str, steps: list[dict]) -> None:
        # 同一个实例重复注册时直接替换，保证测试和回放可以重置轨迹。
        self.tracks[instance_id] = steps

    def replace_all(self, tracks: dict[str, list[dict]]) -> None:
        # 内存回放每次注入完整轨迹集合，旧实例必须整体替换掉。
        self.tracks = dict(tracks)

    def clear(self) -> None:
        # 回放结束后清空轨迹，避免下一轮复用上一轮答案。
        self.tracks.clear()

    def count(self) -> int:
        # 管理接口返回当前实例数，便于 runner 和测试确认注入规模。
        return len(self.tracks)

    def step(self, instance_id: str, index: int) -> dict:
        # 未注册实例也要稳定返回，方便攻击链回放时保持字节级可复现。
        steps = self.tracks.get(instance_id)
        if steps is None:
            content = self.fallback_content(f"{instance_id}:{index}")
            return {"role": "assistant", "content": content}

        # 已注册轨迹走完后返回空内容，表示模型停止输出。
        if index >= len(steps):
            return {"role": "assistant", "content": ""}
        return steps[index]

    @staticmethod
    def fallback_content(seed: str) -> str:
        # fallback 只暴露短哈希，不把原始实例信息写进模型响应。
        digest = hashlib.sha256(seed.encode()).hexdigest()[:12]
        return f"[stub:{digest}]"
