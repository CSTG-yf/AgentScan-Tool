"""Build an evidence-indexed, three-mode AgentRange evaluation report."""

from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import os
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Any

from metrics import summarize_instances
from run_store import EvaluationRun, MODES, _atomic_json, _now, _read_json

METRICS = (
    "precision", "recall", "fpr", "fnr", "effective_block_rate",
    "normal_business_success_rate",
)
COUNTS = (
    "TP", "FP", "FN", "TN", "unverified", "effective_blocks",
    "attack_side_effects", "normal_business_success", "normal_business_blocked",
)


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _atomic_text(path: Path, value: str) -> None:
    with NamedTemporaryFile(mode="w", encoding="utf-8", newline="", dir=path.parent, prefix=".evaluation-", delete=False) as tmp:
        temporary = Path(tmp.name)
        try:
            tmp.write(value)
            tmp.flush()
            os.fsync(tmp.fileno())
        except BaseException:
            temporary.unlink(missing_ok=True)
            raise
    try:
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _display(value: Any) -> str:
    return "未验证" if value is None else str(value)


def _csv_safe(value: Any) -> Any:
    if isinstance(value, str) and value.lstrip().startswith(("=", "+", "-", "@")):
        return "'" + value
    return value


def _csv_rows(summaries: dict[str, dict]) -> str:
    output = io.StringIO(newline="")
    writer = csv.writer(output)
    writer.writerow((
        "mode", "instance_id", "scenario", "label", "detection_cell", "effect",
        "effective_block", "evidence_refs", "effect_evidence_ref",
    ))
    for mode in MODES:
        for row in summaries[mode]["instances"]:
            writer.writerow(tuple(_csv_safe(value) for value in (
                mode, row["instance_id"], row.get("scenario") or "", row["label"],
                row["detection_cell"], row["effect"], row["effective_block"],
                json.dumps(row.get("evidence_refs") or [], ensure_ascii=False),
                row.get("effect_evidence_ref") or "",
            )))
    return output.getvalue()


def _markdown(run_id: str, summaries: dict[str, dict], evidence_index: dict[str, str]) -> str:
    lines = [
        f"# AgentRange 评测批次 {run_id}", "",
        "指标仅在实例证据完整时给出；未验证不等于零，也不等于攻击被阻止。", "",
        "| 指标 | Baseline | Observe | Action |", "| --- | ---: | ---: | ---: |",
    ]
    for key in COUNTS:
        lines.append(f"| {key} | " + " | ".join(_display(summaries[mode]["counts"].get(key)) for mode in MODES) + " |")
    for key in METRICS:
        lines.append(f"| {key} | " + " | ".join(_display(summaries[mode]["metrics"].get(key)) for mode in MODES) + " |")
    lines.extend(["", "## 证据覆盖", "", "| 模式 | 真值实例 | 观测实例 | 检测可验证 | 副作用可验证 |", "| --- | ---: | ---: | ---: | ---: |"])
    for mode in MODES:
        coverage = summaries[mode]["coverage"]
        lines.append(
            f"| {mode} | {coverage['truth_instances']} | {coverage['observed_instances']} | "
            f"{coverage['detection_verified']} | {coverage['effect_verified']} |"
        )
    lines.extend(["", "## 原始证据索引（SHA-256）", ""])
    for filename, digest in sorted(evidence_index.items()):
        lines.append(f"- `{filename}`: `{digest}`")
    lines.append("")
    return "\n".join(lines)


def build_report(run_path: Path) -> dict[str, Any]:
    run = EvaluationRun(run_path)
    manifest = run.manifest()
    if manifest.get("status") != "completed" or any(
        manifest["modes"][mode]["status"] != "completed" for mode in MODES
    ):
        raise ValueError("all three modes must be complete before building a report")
    truth = _read_json(run.path / "truth.json")
    summaries: dict[str, dict] = {}
    indexed_files = ["truth.json", "manifest.json"]
    for mode in MODES:
        observations_name = manifest["modes"][mode]["observations"]
        report_name = manifest["modes"][mode]["report"]
        if observations_name != f"{mode}-observations.json" or report_name != f"{mode}-report.json":
            raise ValueError("unexpected mode evidence path")
        observations = _read_json(run.path / observations_name)
        mode_report = _read_json(run.path / report_name)
        recalculated = summarize_instances(truth, observations)
        if mode_report.get("mode") != mode or mode_report.get("summary") != recalculated:
            raise ValueError(f"{mode} report does not match instance observations")
        summaries[mode] = recalculated
        indexed_files.extend((observations_name, report_name))
        for optional in (
            f"{mode}-receipts.jsonl", f"{mode}-mcp-before.json", f"{mode}-mcp-after.json",
            f"{mode}-effect-observations.json", f"{mode}-gateway-detections.json",
            f"{mode}-detection-observations.json", f"{mode}-gateway-events.json",
            f"{mode}-enforcement-observations.json",
        ):
            if (run.path / optional).is_file():
                indexed_files.append(optional)

    evidence_index = {filename: _digest(run.path / filename) for filename in indexed_files}
    report = {
        "schema_version": 1,
        "run_id": manifest["run_id"],
        "generated_at": _now(),
        "baseline": manifest.get("baseline", {}),
        "modes": {mode: {
            "counts": summaries[mode]["counts"],
            "metrics": summaries[mode]["metrics"],
            "coverage": summaries[mode]["coverage"],
        } for mode in MODES},
        "evidence_sha256": evidence_index,
    }
    _atomic_json(run.path / "comparison-report.json", report)
    _atomic_text(run.path / "comparison-instances.csv", _csv_rows(summaries))
    _atomic_text(run.path / "comparison-report.md", _markdown(manifest["run_id"], summaries, evidence_index))
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run_path", type=Path)
    args = parser.parse_args()
    build_report(args.run_path)
    print(args.run_path / "comparison-report.md")


if __name__ == "__main__":
    main()
