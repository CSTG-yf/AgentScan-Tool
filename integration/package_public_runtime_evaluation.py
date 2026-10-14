"""Create privacy-trimmed runtime evaluation imports from a completed local pair."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from integration.evaluation_export import export_runtime  # noqa: E402

EVIDENCE = "docs/evidence/20261009-mac-full-pair"
OBSERVATION_FIELDS = {
    "business_success", "decision", "detector_block_evidence", "e2e_latency_ms",
    "inspect_latency_ms", "inspect_unavailable_count", "instance_id", "mode",
    "response_bytes", "response_phase", "response_raw_action", "response_sha256",
    "side_effect_probe_refs", "side_effect_probe_status", "side_effect_reached",
    "status", "timeout", "transport_decision", "valid", "would_block",
}
EVENT_FIELDS = {
    "action", "actor", "connector", "decision", "destination_app", "event_id",
    "http_method", "http_path", "instance_id", "latency_ms", "mcp_server",
    "proxy_kind", "severity", "stage", "target", "timestamp", "tool_name",
    "trace_id",
}


def canonical(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def file_hash(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def safe_observation(value: dict) -> dict:
    result = {key: value[key] for key in OBSERVATION_FIELDS if key in value}
    detections = result.get("detector_block_evidence")
    if isinstance(detections, list):
        cleaned = []
        for item in detections:
            if not isinstance(item, dict):
                continue
            evidence = {key: item[key] for key in (
                "destination", "enforced", "raw_action", "severity", "stage",
                "timestamp", "tool_name", "would_block",
            ) if key in item}
            reason = item.get("reason", "")
            match = re.match(r"^matched:\s*([A-Z0-9][A-Z0-9_.-]{0,100})", reason)
            if match:
                evidence["reason"] = f"matched: {match.group(1)}"
            cleaned.append(evidence)
        result["detector_block_evidence"] = cleaned
    return result


def safe_event(value: dict) -> dict:
    return {key: value[key] for key in EVENT_FIELDS if key in value}


def trim_source(source: str, run_root: Path) -> str:
    value = source.replace(str(run_root.resolve()) + "/", "bench/runs/20261009-mac-full-pair/")
    return f"{EVIDENCE}/raw-manifest.json · {value}"


def package_run(run_root: Path, mode: str, source_hashes: dict[str, str]) -> dict:
    run_dir = run_root / mode
    result = export_runtime(
        run_dir,
        platform="macOS 本机公开靶场",
        comparison_group="",
    )
    result["name"] = f"Agent 风险监控与阻断 / {('防护组' if mode == 'action' else '基线组')} / 2026-10-09"
    result["evidence_directory"] = EVIDENCE
    result["notes"] = [
        "公开靶场历史回放批次；不是当前软件版本的实时数据，也不是官方隐藏集成绩。",
        "实例证据已移除提示词、请求正文、响应正文和攻击链正文；保留审计事件摘要、检测/阻断回执、副作用探针与原始性能采样。",
        "源码版本和靶场/语料哈希取自本次回放清单；原始配置哈希与镜像摘要未记录，因此相关跨模式指标由看板标记为证据不足。",
    ]

    source_by_kind = {
        "ground_truth": f"bench/runs/20261009-mac-full-pair/{mode}/gt.jsonl",
        "observation": f"bench/runs/20261009-mac-full-pair/{mode}/observations.jsonl",
        "event": f"bench/runs/20261009-mac-full-pair/{mode}/runtime-events.jsonl",
    }
    artifacts = []
    kept = set()
    for artifact in result["artifacts"]:
        kind = artifact["kind"]
        if kind in {"attack_chain", "scan"}:
            continue
        try:
            content = json.loads(artifact["content"])
        except (TypeError, json.JSONDecodeError):
            continue
        if kind == "observation":
            content = safe_observation(content)
        elif kind == "event":
            content = [safe_event(row) for row in content if isinstance(row, dict)]
        artifact["content"] = canonical(content)
        artifact["sha256"] = hashlib.sha256(artifact["content"].encode("utf-8")).hexdigest()
        if kind in source_by_kind:
            raw_path = source_by_kind[kind]
            artifact["source"] = f"{EVIDENCE}/raw-manifest.json · {raw_path} SHA256={source_hashes[raw_path]}"
        else:
            artifact["source"] = trim_source(artifact["source"], run_root)
        artifacts.append(artifact)
        kept.add(artifact["id"])
    result["artifacts"] = artifacts
    for instance in result["instances"]:
        instance["evidence"] = {
            stage: [ref for ref in refs if ref in kept]
            for stage, refs in instance.get("evidence", {}).items()
            if any(ref in kept for ref in refs)
        }
    if len(result["instances"]) != 5200:
        raise ValueError(f"{mode} replay must contain 5,200 runtime instances")
    if any(instance["domain"] != "runtime" for instance in result["instances"]):
        raise ValueError("runtime seed must not include unscored static inventory")
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-root", type=Path, default=ROOT / "bench/runs/20261009-mac-full-pair")
    parser.add_argument("--output-dir", type=Path, default=ROOT / EVIDENCE)
    args = parser.parse_args()
    manifest_path = args.output_dir / "raw-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    hashes = {row["path"]: row["sha256"] for row in manifest["files"]}
    mode = "action"
    source_names = [f"{mode}/gt.jsonl", f"{mode}/observations.jsonl", f"{mode}/runtime-events.jsonl"]
    for name in source_names:
        actual = file_hash(args.run_root / name)
        if actual != hashes[name]:
            raise ValueError(f"source evidence SHA-256 differs from raw manifest: {name}")
    source_hashes = {f"bench/runs/20261009-mac-full-pair/{name}": hashes[name] for name in source_names}
    result = package_run(args.run_root, mode, source_hashes)
    output = args.output_dir / "evaluation-action.json"
    raw = canonical(result) + "\n"
    if len(raw.encode("utf-8")) > 32 * 1024 * 1024:
        raise ValueError("action evaluation exceeds the 32 MB application import limit")
    output.write_text(raw, encoding="utf-8")
    print(f"{mode}: {len(result['instances'])} instances, {len(result['artifacts'])} artifacts, {len(raw.encode('utf-8'))} bytes → {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
