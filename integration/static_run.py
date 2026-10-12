"""Run a source-only arena scan, score frozen labels, and export a dashboard batch."""
from __future__ import annotations

import argparse
from datetime import UTC, datetime
from hashlib import sha256
import json
from pathlib import Path
import platform
import subprocess

import yaml

from integration.static_eval import evaluate
from integration.static_inventory import DEFAULT_RANGE_ROOT, DEFAULT_TAXONOMY, scan
from integration.evaluation_export import export_static

ROOT = Path(__file__).resolve().parents[1]


def arena_hash(root: Path) -> str:
    digest = sha256()
    for path in sorted(item for item in root.rglob("*") if item.is_file() and "__pycache__" not in item.parts):
        digest.update(path.relative_to(root).as_posix().encode())
        digest.update(sha256(path.read_bytes()).hexdigest().encode())
    return digest.hexdigest()


def write_json(path: Path, value: dict) -> None:
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n")


def run_static_evaluation(arena_root: Path, truth_path: Path, output: Path, taxonomy_path: Path = DEFAULT_TAXONOMY) -> dict:
    arena_root, truth_path, output, taxonomy_path = [p.resolve() for p in (arena_root, truth_path, output, taxonomy_path)]
    if output == arena_root or arena_root in output.parents:
        raise ValueError("evaluation output must be outside the scanned arena")
    truth = yaml.safe_load(truth_path.read_text())
    before = arena_hash(arena_root)
    if before != truth["arena_sha256"]:
        raise ValueError("arena differs from independently frozen ground truth")
    config_sources = {"taxonomy": taxonomy_path, "compose": arena_root / "docker-compose.yml", "environment": arena_root / ".env.example"}
    source_hashes = {key: sha256(path.read_bytes()).hexdigest() for key, path in config_sources.items() if path.exists()}
    config_hash = sha256(json.dumps(source_hashes, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    commit = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True, capture_output=True, check=True).stdout.strip()
    started = datetime.now(UTC).isoformat()
    result = scan(arena_root, taxonomy_path)
    finished = datetime.now(UTC).isoformat()
    if arena_hash(arena_root) != before:
        raise ValueError("arena changed during scan; evidence not exported")
    manifest = dict(schema_version=1, scope="current_source_snapshot", mode="observe", platform=f"{platform.system().lower()}-{platform.machine()}", code_version=commit, config_hash=config_hash, config_sources=source_hashes, image_digest="not_applicable:static_source_scan", image_scope="No running image used: static source files only", dataset_hash=before, started_at=started, finished_at=finished, truth_sha256=sha256(truth_path.read_bytes()).hexdigest(), scanner_sha256=sha256((ROOT / "integration/static_inventory.py").read_bytes()).hexdigest(), taxonomy_sha256=source_hashes["taxonomy"])
    result["provenance"] = manifest.copy()
    output.mkdir(parents=True, exist_ok=True)
    scan_path = output / "static-scan.json"
    write_json(scan_path, result)
    evaluated = evaluate(scan_path, truth_path, arena_root)
    write_json(output / "static-eval.json", evaluated)
    manifest["scan_sha256"] = sha256(scan_path.read_bytes()).hexdigest()
    manifest["evaluation_sha256"] = sha256((output / "static-eval.json").read_bytes()).hexdigest()
    write_json(output / "static-run.json", manifest)
    dashboard = export_static(scan_path, truth_path)
    write_json(output / "evaluation.json", dashboard)
    return dict(scan=result, evaluation=evaluated, dashboard=dashboard, manifest=manifest)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--arena-root", type=Path, default=DEFAULT_RANGE_ROOT)
    parser.add_argument("--truth", type=Path, required=True)
    parser.add_argument("--taxonomy", type=Path, default=DEFAULT_TAXONOMY)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    result = run_static_evaluation(args.arena_root, args.truth, args.output_dir, args.taxonomy)
    print(json.dumps(result["evaluation"], ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
