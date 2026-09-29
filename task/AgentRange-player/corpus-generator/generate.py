import argparse
from dataclasses import asdict
import pathlib
import random
import sys

# 直接执行 generate.py 时，补上 attack/ 路径以复用 cat2 轨迹定义。
root = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(root / "attack"))

from events import Event
from templates import render_attack, render_benign

benign_templates = ["B-RD", "B-OPS", "B-SEC", "B-SUP"]
attack_templates = ["C1-A", "C1-B", "C2-A", "C2-B", "C2-C", "C2-D", "M-1"]


def generate(seed: int = 1337, total: int = 5200, malicious_target: int = 80) -> list[Event]:
    rng = random.Random(seed)
    # 恶意事件稀疏散布，保持约 60:1 的良恶比例。
    slots = set(rng.sample(range(total), malicious_target))
    events = []
    attack_index = 0
    for t in range(total):
        if t in slots:
            tmpl = attack_templates[attack_index % len(attack_templates)]
            attack_index += 1
            events.append(render_attack(tmpl, rng, t))
        else:
            events.append(render_benign(benign_templates[t % len(benign_templates)], rng, t))
    return events


def public_record(event: Event) -> dict:
    # corpus 是对外回放输入。真值、预期副作用及预设轨迹必须留在
    # 操作者侧；轨迹只通过 runner 的受控管理接口注入 llm-stub。
    record = asdict(event)
    for private_field in ("malicious", "kind", "evidence", "trajectory"):
        record.pop(private_field, None)
    return record


def trajectory_map(events: list[Event]) -> dict[str, list[dict]]:
    # llm-stub 只需要按实例索引的轨迹集合，runner 会通过管理接口注入内存。
    return {event.instance_id: event.trajectory for event in events if event.trajectory}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate replay corpus in memory only.")
    parser.add_argument("--seed", type=int, default=1337)
    parser.add_argument("--total", type=int, default=5200)
    parser.add_argument("--malicious-target", type=int, default=80)
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    generated = generate(args.seed, args.total, args.malicious_target)
    print(f"generated {len(generated)} events")
