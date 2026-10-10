"""Run an AgentRange replay while collecting a comparable Docker window."""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RANGE_ROOT = ROOT / "task" / "AgentRange-player-full"


def run(args: argparse.Namespace) -> int:
    run_dir = args.run_dir.resolve()
    range_root = Path(getattr(args, "range_root", RANGE_ROOT)).resolve()
    host_gateway_pid = getattr(args, "host_gateway_pid", None)
    if host_gateway_pid is not None and sys.platform != "win32":
        raise ValueError("host gateway sampler currently requires Windows")
    run_dir.mkdir(parents=True, exist_ok=True)
    resource_output = run_dir / "resources.jsonl"
    sampler_stdout = run_dir / "resource-sampler.stdout.log"
    sampler_stderr = run_dir / "resource-sampler.stderr.log"

    sampler_command = [
        sys.executable,
        str(ROOT / "bench" / "resource_sampler.py"),
        "--output",
        str(resource_output),
        "--mode",
        args.mode,
        "--samples",
        str(args.samples),
        "--interval-ms",
        str(args.interval_ms),
    ]
    with sampler_stdout.open("w", encoding="utf-8") as stdout, sampler_stderr.open("w", encoding="utf-8") as stderr:
        sampler = subprocess.Popen(sampler_command, cwd=ROOT, stdout=stdout, stderr=stderr)

    replay_command = [
        sys.executable,
        str(ROOT / "bench" / "live_replay.py"),
        "--run-dir",
        str(run_dir),
        "--mode",
        args.mode,
        "--range-root",
        str(range_root),
        "--seed",
        str(args.seed),
        "--total",
        str(args.total),
        "--malicious-target",
        str(args.malicious_target),
    ]
    if args.only:
        replay_command.extend(["--only", args.only])
    if getattr(args, "target_rate", None) is not None:
        replay_command.extend(["--target-rate", str(args.target_rate)])
    host_sampler = None
    try:
        if host_gateway_pid is not None:
            host_command = [
                shutil.which("pwsh") or shutil.which("powershell") or "pwsh",
                "-NoProfile", "-ExecutionPolicy", "Bypass", "-File",
                str(ROOT / "bench" / "host_gateway_sampler.ps1"),
                "-Output", str(run_dir / "host-gateway.jsonl"),
                "-GatewayProcessId", str(host_gateway_pid),
                "-ReplayProcessId", str(os.getpid()),
                "-IntervalMs", str(args.host_interval_ms),
                "-MaxSamples", str(max(args.samples, 10000)),
                "-Mode", args.mode,
            ]
            with (run_dir / "host-gateway.stdout.log").open("w", encoding="utf-8") as stdout, \
                    (run_dir / "host-gateway.stderr.log").open("w", encoding="utf-8") as stderr:
                host_sampler = subprocess.Popen(
                    host_command, cwd=ROOT, stdout=stdout, stderr=stderr,
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                )
        completed = subprocess.run(replay_command, cwd=ROOT, check=False)
    finally:
        if sampler.poll() is None:
            sampler.terminate()
            try:
                sampler.wait(timeout=10)
            except subprocess.TimeoutExpired:
                sampler.kill()
                sampler.wait(timeout=10)
        if host_sampler is not None and host_sampler.poll() is None:
            host_sampler.terminate()
            try:
                host_sampler.wait(timeout=10)
            except subprocess.TimeoutExpired:
                host_sampler.kill()
                host_sampler.wait(timeout=10)
    return completed.returncode


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-dir", type=Path, required=True)
    parser.add_argument("--mode", choices=("baseline", "observe", "action"), required=True)
    parser.add_argument("--range-root", type=Path, default=RANGE_ROOT)
    parser.add_argument("--seed", type=int, default=1337)
    parser.add_argument("--total", type=int, default=5200)
    parser.add_argument("--malicious-target", type=int, default=80)
    parser.add_argument("--samples", type=int, default=12000)
    parser.add_argument("--interval-ms", type=int, default=500)
    parser.add_argument("--only")
    parser.add_argument("--target-rate", type=float)
    parser.add_argument("--host-gateway-pid", type=int)
    parser.add_argument("--host-interval-ms", type=int, default=2000)
    args = parser.parse_args()
    if args.host_interval_ms < 100:
        parser.error("--host-interval-ms must be at least 100")
    return run(args)


if __name__ == "__main__":
    raise SystemExit(main())
