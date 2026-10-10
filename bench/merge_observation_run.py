"""Merge a targeted AgentRange replay into a compatible base run.

The tool is for controlled differential benchmark iterations: a base run
provides the complete corpus, while a targeted replay replaces observations
for the affected instance ids. A targeted replay may contain a corpus subset;
its rows must still match the corresponding base rows exactly.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import shutil
from typing import Any


def read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"expected object: {path}")
    return value


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                value = json.loads(line)
                if not isinstance(value, dict):
                    raise ValueError(f"expected object row: {path}")
                rows.append(value)
    return rows


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")


def by_instance(rows: list[dict[str, Any]], path: Path) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for row in rows:
        if "instance_id" not in row:
            raise ValueError(f"missing instance_id: {path}")
        instance_id = str(row["instance_id"])
        if instance_id in result:
            raise ValueError(f"duplicate instance_id {instance_id!r}: {path}")
        result[instance_id] = row
    return result


def without_run_id(row: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in row.items() if key != "run_id"}


def merge(base: Path, replacement: Path, output: Path) -> dict[str, Any]:
    base = base.resolve()
    replacement = replacement.resolve()
    output = output.resolve()
    if output == base or output == replacement or base in output.parents or replacement in output.parents:
        raise ValueError("output must be separate from the source runs")
    if output.exists():
        raise FileExistsError(f"output already exists: {output}")
    base_manifest = read_json(base / "run.json")
    replacement_manifest = read_json(replacement / "run.json")
    for key in ("arena_sha256", "mode", "seed"):
        if base_manifest.get(key) != replacement_manifest.get(key):
            raise ValueError(f"manifest mismatch for {key}: {base_manifest.get(key)!r} != {replacement_manifest.get(key)!r}")

    base_gt = read_jsonl(base / "gt.jsonl")
    replacement_gt = read_jsonl(replacement / "gt.jsonl")
    base_gt_by_id = by_instance(base_gt, base / "gt.jsonl")
    replacement_gt_by_id = by_instance(replacement_gt, replacement / "gt.jsonl")
    if set(replacement_gt_by_id) - set(base_gt_by_id):
        raise ValueError("replacement contains instance ids absent from base ground truth")
    for instance_id, row in replacement_gt_by_id.items():
        if without_run_id(row) != without_run_id(base_gt_by_id[instance_id]):
            raise ValueError(f"ground truth mismatch for {instance_id}")

    base_public = by_instance(read_jsonl(base / "public-corpus.jsonl"), base / "public-corpus.jsonl")
    replacement_public = by_instance(
        read_jsonl(replacement / "public-corpus.jsonl"), replacement / "public-corpus.jsonl"
    )
    replacement_ids = set(replacement_gt_by_id)
    if set(replacement_public) != replacement_ids:
        raise ValueError("replacement public corpus does not cover exactly its ground truth")
    for instance_id, row in replacement_public.items():
        if base_public.get(instance_id) != row:
            raise ValueError(f"public corpus mismatch for {instance_id}")

    base_observations = read_jsonl(base / "observations.jsonl")
    replacement_observations = read_jsonl(replacement / "observations.jsonl")
    base_observation_by_id = by_instance(base_observations, base / "observations.jsonl")
    replacement_observation_by_id = by_instance(
        replacement_observations, replacement / "observations.jsonl"
    )
    replacement_observation_ids = set(replacement_observation_by_id)
    if replacement_observation_ids != replacement_ids:
        raise ValueError("replacement observations do not cover exactly its ground truth")
    if replacement_ids - set(base_observation_by_id):
        raise ValueError("replacement contains instance ids absent from base observations")
    merged = [row for row in base_observations if str(row["instance_id"]) not in replacement_ids]
    merged.extend(replacement_observations)
    if {str(row["instance_id"]) for row in merged} != set(base_gt_by_id) or len(merged) != len(base_observations):
        raise ValueError("merged observations do not preserve base coverage")
    merged.sort(key=lambda row: str(row["instance_id"]))

    output.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(base, output)
    write_jsonl(output / "observations.jsonl", merged)
    metadata = {
        "schema_version": 1,
        "kind": "differential_observation_merge",
        "base_run": str(base),
        "replacement_run": str(replacement),
        "replacement_instances": len(replacement_ids),
        "merged_instances": len(merged),
        "replacement_instance_ids_sha256": __import__("hashlib").sha256(
            "\n".join(sorted(replacement_ids)).encode("utf-8")
        ).hexdigest(),
    }
    (output / "differential-merge.json").write_text(json.dumps(metadata, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return metadata


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", type=Path, required=True)
    parser.add_argument("--replacement", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(merge(args.base.resolve(), args.replacement.resolve(), args.output.resolve()), ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
