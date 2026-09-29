"""Freeze a single AgentRange corpus and operator-only truth for three-mode evaluation."""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

RANGE_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(RANGE_ROOT / "corpus-generator"))

from generate import generate, public_record, trajectory_map  # noqa: E402
from run_store import EvaluationRun  # noqa: E402


def source_revision() -> dict[str, str | bool]:
    repository = RANGE_ROOT.parents[1]
    try:
        revision = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=repository, check=True,
            capture_output=True, text=True,
        ).stdout.strip()
        dirty = bool(subprocess.run(
            ["git", "status", "--porcelain"], cwd=repository, check=True,
            capture_output=True, text=True,
        ).stdout.strip())
        return {"commit": revision, "working_tree_dirty": dirty}
    except (OSError, subprocess.CalledProcessError):
        return {"commit": "unknown", "working_tree_dirty": True}


def prepare_run(
    output_root: Path, *, seed: int = 1337, total: int = 5200,
    malicious_target: int = 80, scenarios: set[str] | None = None,
) -> EvaluationRun:
    if output_root.resolve().is_relative_to(RANGE_ROOT):
        raise ValueError("evaluation output must be outside the AgentRange bind-mounted tree")
    if total < 1 or not 0 <= malicious_target <= total:
        raise ValueError("total must be positive and malicious_target must be within total")
    generated = generate(seed, total, malicious_target)
    if scenarios:
        generated = [event for event in generated if event.scenario in scenarios]
    if not generated:
        raise ValueError("scenario selection produced no instances")
    truth = [{
        "instance_id": event.instance_id,
        "scenario": event.scenario,
        "label": "attack" if event.malicious else "benign",
        "expected_outcome": event.evidence.get("outcome"),
    } for event in generated]
    run = EvaluationRun.create(output_root, truth, {
        "source": source_revision(),
        "generator": {"seed": seed, "total": total, "malicious_target": malicious_target},
        "selected_scenarios": sorted(scenarios) if scenarios else "all",
    })
    run.save_corpus([public_record(event) for event in generated], trajectory_map(generated))
    return run


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--seed", type=int, default=1337)
    parser.add_argument("--total", type=int, default=5200)
    parser.add_argument("--malicious-target", type=int, default=80)
    parser.add_argument("--scenario", action="append", dest="scenarios")
    args = parser.parse_args()
    run = prepare_run(
        args.output_root, seed=args.seed, total=args.total,
        malicious_target=args.malicious_target,
        scenarios=set(args.scenarios) if args.scenarios else None,
    )
    print(run.path)


if __name__ == "__main__":
    main()
