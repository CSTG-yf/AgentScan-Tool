"""Run one AgentRange mode and persist process evidence.

Gateway mode configuration and side-effect probes remain explicit operator
steps. This wrapper only makes the replay command, mode, and durable output
directory reproducible.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RANGE_ROOT = ROOT / "task" / "AgentRange-player"


def _docker_available() -> tuple[bool, str]:
    docker = shutil.which("docker")
    if not docker:
        return False, "docker executable not found"
    result = subprocess.run([docker, "version", "--format", "{{.Server.Version}}"], capture_output=True, text=True, check=False)
    if result.returncode != 0:
        return False, result.stderr.strip() or "Docker daemon unavailable"
    return True, result.stdout.strip()


def run(args: argparse.Namespace) -> int:
    available, detail = _docker_available()
    output_dir = args.run_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    started = datetime.now(UTC).isoformat()
    process_record = {
        "schema_version": 1,
        "run_id": output_dir.name,
        "mode": args.mode,
        "started_at": started,
        "docker_available": available,
        "docker_version": detail if available else None,
        "command": None,
        "returncode": None,
    }
    if not available:
        process_record["error"] = detail
        (output_dir / "replay-process.json").write_text(json.dumps(process_record, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        return 2

    runner = args.range_root.resolve() / "scenario-runner" / "runner.py"
    command = [
        sys.executable,
        str(runner),
        "--seed",
        str(args.seed),
        "--total",
        str(args.total),
        "--malicious-target",
        str(args.malicious_target),
        "--output-dir",
        str(output_dir),
    ]
    if args.only:
        command.insert(2, args.only)
    process_record["command"] = command
    env = os.environ.copy()
    env["AGENTRANGE_MODE"] = args.mode
    env["AGENTRANGE_RUN_DIR"] = str(output_dir)
    completed = subprocess.run(command, cwd=ROOT, env=env, capture_output=True, text=True, check=False)
    (output_dir / "replay.stdout.log").write_text(completed.stdout, encoding="utf-8")
    (output_dir / "replay.stderr.log").write_text(completed.stderr, encoding="utf-8")
    process_record["returncode"] = completed.returncode
    process_record["finished_at"] = datetime.now(UTC).isoformat()
    (output_dir / "replay-process.json").write_text(json.dumps(process_record, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return completed.returncode


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-dir", type=Path, required=True)
    parser.add_argument("--mode", choices=("baseline", "observe", "action"), required=True)
    parser.add_argument("--range-root", type=Path, default=RANGE_ROOT)
    parser.add_argument("--seed", type=int, default=1337)
    parser.add_argument("--total", type=int, default=5200)
    parser.add_argument("--malicious-target", type=int, default=80)
    parser.add_argument("--only")
    return run(parser.parse_args())


if __name__ == "__main__":
    raise SystemExit(main())
