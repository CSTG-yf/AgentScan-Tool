"""Export existing evidence into the Gateway capability dashboard contract.

This imports completed evidence only; it does not launch or alter arena runs.
Missing historical provenance and missing evidence remain missing.
"""
from __future__ import annotations

import argparse
from bisect import bisect_left
from collections import defaultdict
from datetime import datetime
from hashlib import sha256
import json
from pathlib import Path
import statistics


def read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}


def jsonl(path: Path):
    if path.exists():
        with path.open(encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, 1):
                if line.strip():
                    yield line_number, json.loads(line)


class Exporter:
    def __init__(self):
        self.artifacts = []

    def artifact(self, key: str, kind: str, content, source: str) -> str:
        raw = json.dumps(content, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        self.artifacts.append(dict(id=key, kind=kind, source=source, content=raw, sha256=sha256(raw.encode()).hexdigest()))
        return key

    def series(self, key: str, kind: str, scope: str, basis: str, samples: list, expected: int, complete: bool, start: str, end: str, source: str) -> dict:
        artifact = self.artifact(key, "samples", samples, source)
        return dict(id=key, kind=kind, scope=scope, basis=basis, samples=samples, expected_samples=expected, complete=complete, window_start=start, window_end=end, artifact_id=artifact)


def export_runtime(directory: Path, *, config_hash="", image_digest="", platform="", comparison_group="") -> dict:
    directory = directory.resolve()
    manifest = read_json(directory / "run.json")
    process = read_json(directory / "replay-process.json")
    if not manifest or not process:
        raise ValueError("run.json and replay-process.json are required")
    truth_rows = [row for _, row in jsonl(directory / "gt.jsonl")]
    if not truth_rows:
        raise ValueError("independent gt.jsonl is required")
    if manifest.get("total") != len(truth_rows):
        raise ValueError("ground truth sample count differs from run manifest")
    expected_hash = manifest.get("ground_truth_sha256")
    actual_hash = sha256((directory / "gt.jsonl").read_bytes()).hexdigest()
    if expected_hash and expected_hash != actual_hash:
        raise ValueError("ground truth hash differs from run manifest")
    corpus_hash = sha256((directory / "public-corpus.jsonl").read_bytes()).hexdigest()
    if manifest.get("public_corpus_sha256") != corpus_hash:
        raise ValueError("public corpus hash differs from run manifest")
    labels = {}
    truth_by_id = {row["instance_id"]: row for row in truth_rows}
    for row in truth_rows:
        if row["instance_id"] in labels or row.get("label") not in ("malicious", "benign"):
            raise ValueError("duplicate instance or unsupported truth label")
        labels[row["instance_id"]] = row["label"] == "malicious"
    out = Exporter()
    truth_id = out.artifact("runtime-truth", "ground_truth", {"runtime": labels}, f"{directory}/gt.jsonl; original SHA256={actual_hash}")
    times = {}
    raw_events = defaultdict(list)
    for line, event in jsonl(directory / "runtime-events.jsonl"):
        key = event.get("instance_id")
        if key not in labels:
            continue
        if event.get("timestamp") and key not in times:
            times[key] = event["timestamp"]
        # Keep three directly attributable raw events; retain all positive detection events.
        if len(raw_events[key]) < 3 or event.get("severity") not in (None, "", "NONE", "INFO"):
            raw_events[key].append((line, event))
    instances = []
    inspect_samples, e2e_samples = [], []
    seen = set()
    for line, obs in jsonl(directory / "observations.jsonl"):
        key = obs.get("instance_id")
        if key in seen:
            raise ValueError("duplicate observation instance")
        seen.add(key)
        evidence = {}
        observation = out.artifact(f"obs:{key}", "observation", obs, f"{directory}/observations.jsonl:{line}")
        evidence["decision"] = [observation]
        if raw_events[key]:
            evidence["event"] = [out.artifact(f"events:{key}", "event", [item for _, item in raw_events[key]], f"{directory}/runtime-events.jsonl lines {','.join(str(number) for number, _ in raw_events[key])}")]
        detector = obs.get("detector_block_evidence", [])
        hit = bool(detector) or obs.get("would_block") is True
        if detector:
            evidence["detection"] = [out.artifact(f"detection:{key}", "detection", detector, f"{directory}/observations.jsonl:{line}:detector_block_evidence")]
        executed = any(item.get("enforced") is True for item in detector)
        response_status = "executed" if executed else "would_block" if manifest["mode"] == "observe" and hit else "not_requested" if not hit else ""
        if executed:
            evidence["response"] = [out.artifact(f"response:{key}", "response", [item for item in detector if item.get("enforced") is True], f"{directory}/observations.jsonl:{line}:enforcement_receipt")]
        side_effect = obs.get("side_effect_reached") if obs.get("side_effect_probe_status") == "complete" else None
        probes = obs.get("side_effect_probe_refs", [])
        if probes and side_effect is not None:
            evidence["side_effect"] = [out.artifact(f"side-effect:{key}", "side_effect", {"probes": probes, "side_effect_reached": side_effect, "status": obs.get("side_effect_probe_status")}, f"{directory}/observations.jsonl:{line}:side_effect_probe_refs")]
        truth = truth_by_id.get(key, {})
        connector = "langflow" if truth.get("expected_target") == "framework.langflow" else "opspilot" if truth else ""
        predicted = hit if obs.get("valid") is True and obs.get("timeout") is False and obs.get("inspect_unavailable_count") == 0 else None
        instance = dict(id=key, domain="runtime", scenario=truth.get("scenario_id", ""), connector=connector, predicted=predicted, business_success=obs.get("business_success"), decision=str(obs.get("decision", "")).upper(), response_status=response_status, actually_blocked=executed if detector or obs.get("decision") == "allow" else None, side_effect_occurred=side_effect, evidence=evidence)
        instances.append(instance)
        at = times.get(key)
        if at:
            for field, target in [("inspect_latency_ms", inspect_samples), ("e2e_latency_ms", e2e_samples)]:
                if predicted is not None and isinstance(obs.get(field), (int, float)):
                    target.append(dict(at=at, value=obs[field]))
    # Attack chains are retained per malicious instance. They are historical joins,
    # not a new production correlation algorithm.
    chains_path = directory / "attack-chains.json"
    chains = read_json(chains_path).get("chains", []) if chains_path.exists() else []
    chain_by_id = {chain.get("instance_id"): chain for chain in chains if labels.get(chain.get("instance_id"))}
    for instance in instances:
        chain = chain_by_id.get(instance["id"])
        if chain:
            instance["evidence"]["attack_chain"] = [out.artifact(f"chain:{instance['id']}", "attack_chain", chain, f"{chains_path}:chains[instance_id={instance['id']}]")]
    start, end = process["started_at"], process["finished_at"]
    series = []
    for key, samples in [("inspect_ms", inspect_samples), ("e2e_ms", e2e_samples)]:
        if samples:
            series.append(out.series(key, key, "all", "每实例一次；原始 observation 时延；时间来自该实例首条审计事件", samples, len(labels), len(samples) == len(labels), start, end, str(directory / "observations.jsonl")))
    resources = [row for _, row in jsonl(directory / "resources.jsonl")]
    host = [row for _, row in jsonl(directory / "host-gateway.jsonl")]
    started, finished = datetime.fromisoformat(start), datetime.fromisoformat(end)
    def in_window(row):
        return started <= datetime.fromisoformat(row["timestamp"]) <= finished
    containers = defaultdict(list)
    for row in resources:
        if in_window(row):
            containers[row["container"]].append(dict(at=row["timestamp"], value=row["cpu_pct"]))
    for name, samples in sorted(containers.items()):
        series.append(out.series(f"cpu:{name}", "cpu_pct", f"container:{name}", "容器 CPU %；100% 表示一个逻辑核", samples, len(samples), True, start, end, str(directory / "resources.jsonl")))
    host_window = [row for row in host if in_window(row)]
    if host_window:
        samples = [dict(at=row["timestamp"], value=row["cpu_host_pct"]) for row in host_window]
        series.append(out.series("cpu:gateway", "cpu_pct", "gateway", f"宿主总 CPU 百分比，按逻辑核数归一化；logical_processors={host_window[0]['logical_processors']}", samples, len(samples), True, start, end, str(directory / "host-gateway.jsonl")))
        snapshots = defaultdict(dict)
        for row in resources:
            if "defenseclaw-" in row["container"] and in_window(row):
                snapshots[datetime.fromisoformat(row["timestamp"])][row["container"]] = row["cpu_pct"]
        host = sorted(host, key=lambda row: row["timestamp"])
        host_times = [datetime.fromisoformat(row["timestamp"]) for row in host]
        intervals = [(b - a).total_seconds() for a, b in zip(host_times, host_times[1:])]
        tolerance = max(5, 3 * statistics.median(intervals)) if intervals else 5
        processors = {row["logical_processors"] for row in host}
        expected_containers = set().union(*(set(snapshot) for snapshot in snapshots.values())) if snapshots else set()
        combined = []
        if len(processors) == 1 and next(iter(processors)) > 0:
            for at, snapshot in sorted(snapshots.items()):
                index = bisect_left(host_times, at)
                candidates = host[max(0, index - 1):index + 1]
                nearest = min(candidates, key=lambda row: abs((datetime.fromisoformat(row["timestamp"]) - at).total_seconds()))
                if abs((datetime.fromisoformat(nearest["timestamp"]) - at).total_seconds()) <= tolerance and set(snapshot) == expected_containers:
                    combined.append(dict(at=at.isoformat(), value=nearest["cpu_host_pct"] + sum(snapshot.values()) / nearest["logical_processors"]))
        if combined:
            series.append(out.series("cpu:defense-chain", "cpu_pct", "defense_chain", f"宿主总 CPU 百分比：Gateway + 全部 defenseclaw 容器 CPU / 宿主逻辑核数；按最近时间对齐；logical_processors={next(iter(processors))}；containers={','.join(sorted(expected_containers))}", combined, len(snapshots), len(combined) == len(snapshots), start, end, f"{directory}/host-gateway.jsonl + resources.jsonl"))
    notes = ["历史回放导入；保留已采集的审计 Detection / Decision / 执行回执及副作用证据。原始事件按实例保留前三条和全部风险事件，攻击链保留恶意实例。", "Connector 维度来自独立真值集的 expected_target，仅用于评测分组。"]
    if not config_hash or not image_digest:
        notes.append("历史批次未记录完整配置哈希或镜像摘要，模式比较和 CPU 增量显示为未评测。")
    return dict(name=f"{directory.parent.name} / {manifest['mode']}", mode=manifest["mode"], platform=platform, code_version=manifest.get("git_commit", ""), config_hash=config_hash, image_digest=image_digest, dataset_hash=corpus_hash, static_dataset_hash=manifest.get("arena_sha256", ""), comparison_group=comparison_group or directory.parent.name, static_truth={}, runtime_truth=dict(artifact_id=truth_id, dataset_hash=corpus_hash), started_at=start, finished_at=end, status="completed" if process.get("returncode", process.get("exit_code", 0)) == 0 and len(seen) == len(labels) else "failed", evidence_directory=str(directory), notes=notes, instances=instances, artifacts=out.artifacts, series=series)


def export_static(scan_path: Path, truth_path: Path) -> dict:
    import yaml
    scan = read_json(scan_path)
    truth = yaml.safe_load(truth_path.read_text(encoding="utf-8"))
    out = Exporter()
    labels = {"asset": {key: True for key in truth["asset_ids"]}, "risk": {f"{rule}:{asset}": True for rule, asset in truth["risk_pairs"]}}
    truth_id = out.artifact("static-truth", "ground_truth", labels, str(truth_path.resolve()))
    scan_id = out.artifact("static-scan", "scan", scan, str(scan_path.resolve()))
    manifest_path = scan_path.with_name("static-run.json")
    manifest = read_json(manifest_path)
    scan_refs = [scan_id]
    if manifest:
        if manifest.get("scan_sha256") != sha256(scan_path.read_bytes()).hexdigest() or manifest.get("truth_sha256") != sha256(truth_path.read_bytes()).hexdigest():
            raise ValueError("static scan or truth differs from execution manifest")
        if manifest.get("evaluation_sha256") != sha256(scan_path.with_name("static-eval.json").read_bytes()).hexdigest():
            raise ValueError("static evaluation differs from execution manifest")
        scan_refs.append(out.artifact("static-run", "manifest", manifest, str(manifest_path.resolve())))
    assets = {row["id"]: row for row in scan["assets"]}
    findings = defaultdict(list)
    for row in scan["findings"]:
        findings[f"{row['rule_id']}:{row['asset_id']}"].append(row)
    instances = []
    for key in sorted(set(labels["asset"]) | set(assets)):
        instances.append(dict(id=key, domain="asset", asset_type=assets.get(key, {}).get("type", key.split(".")[0]), predicted=key in assets, evidence={"scan": list(scan_refs)}))
    for key in sorted(set(labels["risk"]) | set(findings)):
        asset_id = key.split(":", 1)[1]
        kind = "dangerous_config" if key.startswith("AR-CONFIG-") else "malicious_skill" if asset_id.startswith("skill.") else "malicious_mcp" if asset_id.startswith("mcp.") else "other"
        evidence = {"scan": list(scan_refs)}
        if key in findings:
            evidence["detection"] = [out.artifact(f"finding:{len(instances)}", "detection", findings[key], str(scan_path.resolve()))]
        instances.append(dict(id=key, domain="risk", asset_type=asset_id.split(".")[0], risk_kind=kind, predicted=key in findings, evidence=evidence))
    # A historical score file independently binds this scan to the frozen arena.
    evaluated = read_json(scan_path.with_name("static-eval.json"))
    dataset = evaluated.get("arena_sha256", "")
    if not dataset:
        raise ValueError("static-eval.json is required to bind this historical scan to its dataset")
    if manifest and manifest.get("dataset_hash") != dataset:
        raise ValueError("static dataset differs from execution manifest")
    notes = ["独立冻结的本地静态真值集；仅代表该数据集的资产与风险覆盖，不代表所有 Agent 平台。"]
    if manifest:
        notes.extend(["本批次在当前靶场源文件上实际执行静态扫描，未启动容器或执行工具调用。", "真值包含独立 MCP 工具资产；未发现的工具按漏报计入。插件无样本，保持未评测。"])
    return dict(name=f"静态资产 / {scan_path.parent.name}", mode=manifest.get("mode", "action"), platform=manifest.get("platform", "local_frozen_fixture"), code_version=manifest.get("code_version", ""), config_hash=manifest.get("config_hash", ""), image_digest=manifest.get("image_digest", ""), dataset_hash=dataset, static_dataset_hash=dataset, comparison_group="", static_truth=dict(artifact_id=truth_id, dataset_hash=truth["arena_sha256"]), runtime_truth={}, started_at=manifest.get("started_at", scan.get("generated_at", "")), finished_at=manifest.get("finished_at", scan.get("generated_at", "")), status="completed", evidence_directory=str(scan_path.parent.resolve()), notes=notes, instances=instances, artifacts=out.artifacts, series=[])



def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-dir", type=Path)
    parser.add_argument("--static-scan", type=Path)
    parser.add_argument("--static-truth", type=Path)
    parser.add_argument("--platform", default="")
    parser.add_argument("--config-hash", default="")
    parser.add_argument("--image-digest", default="")
    parser.add_argument("--comparison-group", default="")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.run_dir:
        result = export_runtime(args.run_dir, platform=args.platform, config_hash=args.config_hash, image_digest=args.image_digest, comparison_group=args.comparison_group)
    elif args.static_scan and args.static_truth:
        result = export_static(args.static_scan, args.static_truth)
    else:
        parser.error("choose --run-dir or --static-scan with --static-truth")
    if args.run_dir and args.static_scan and args.static_truth:
        static = export_static(args.static_scan, args.static_truth)
        result["static_truth"] = static["static_truth"]
        result["instances"].extend(static["instances"])
        result["artifacts"].extend(static["artifacts"])
        result["notes"].extend(static["notes"])
        if static["static_truth"]["dataset_hash"] != result["static_dataset_hash"]:
            result["notes"].append("静态冻结真值与本轮靶场哈希不同，静态指标显示为证据不足。")
    raw = json.dumps(result, ensure_ascii=False, separators=(",", ":"))
    if len(raw.encode()) > 32 * 1024 * 1024:
        raise ValueError("export exceeds the 32 MB import limit")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(raw + "\n", encoding="utf-8")
    print(f"exported {len(result['instances'])} instances and {len(result['artifacts'])} artifacts to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
