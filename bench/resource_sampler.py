"""Collect timestamped Docker resource samples for AgentRange runs.

The scorer treats missing samples as unknown. This command never fabricates a
zero CPU value when Docker is unavailable.
"""

from __future__ import annotations

import argparse
from contextlib import contextmanager
import json
import os
import subprocess
import threading
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


_THREAD_LOCKS: dict[str, threading.Lock] = {}
_THREAD_LOCKS_GUARD = threading.Lock()


def _thread_lock(path: Path) -> threading.Lock:
    key = str(path.resolve())
    with _THREAD_LOCKS_GUARD:
        return _THREAD_LOCKS.setdefault(key, threading.Lock())


@contextmanager
def _append_lock(output: Path):
    """Serialize JSONL appends across threads and sampler processes.

    The sampler is commonly run from a second terminal while a replay is in
    progress, and retries can accidentally start a second sampler for the
    same output.  A lock sidecar keeps each JSONL record intact without
    changing the raw sample format or silently dropping a writer's rows.
    """
    lock_path = Path(f"{output}.lock")
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    thread_lock = _thread_lock(lock_path)
    with thread_lock:
        with lock_path.open("a+b") as lock_handle:
            if lock_handle.seek(0, os.SEEK_END) == 0:
                lock_handle.write(b"\0")
                lock_handle.flush()
            lock_handle.seek(0)
            if os.name == "nt":
                import msvcrt

                while True:
                    try:
                        msvcrt.locking(lock_handle.fileno(), msvcrt.LK_NBLCK, 1)
                        break
                    except OSError:
                        time.sleep(0.01)
                try:
                    yield
                finally:
                    lock_handle.seek(0)
                    msvcrt.locking(lock_handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                fcntl.flock(lock_handle.fileno(), fcntl.LOCK_EX)
                try:
                    yield
                finally:
                    fcntl.flock(lock_handle.fileno(), fcntl.LOCK_UN)


def _percent(raw: Any) -> float | None:
    try:
        return float(str(raw).strip().rstrip("%"))
    except (TypeError, ValueError):
        return None


def docker_stats(containers: list[str] | None = None) -> list[dict[str, Any]]:
    command = ["docker", "stats", "--no-stream", "--format", "{{json .}}"]
    if containers:
        command.extend(containers)
    completed = subprocess.run(command, capture_output=True, text=True, check=False)
    if completed.returncode != 0:
        raise RuntimeError(completed.stderr.strip() or "docker stats failed")
    rows: list[dict[str, Any]] = []
    for line in completed.stdout.splitlines():
        if not line.strip():
            continue
        payload = json.loads(line)
        rows.append(
            {
                "container": payload.get("Name") or payload.get("ID"),
                "cpu_pct": _percent(payload.get("CPUPerc")),
                "memory_usage": payload.get("MemUsage"),
                "memory_pct": _percent(payload.get("MemPerc")),
            }
        )
    return rows


def sample(output: Path, *, mode: str, samples: int, interval_ms: int, containers: list[str] | None = None, baseline_cpu_pct: float | None = None) -> int:
    if mode not in {"baseline", "observe", "action"}:
        raise ValueError(f"unsupported mode: {mode}")
    output.parent.mkdir(parents=True, exist_ok=True)
    for index in range(samples):
        captured_at = datetime.now(UTC).isoformat()
        rows = docker_stats(containers)
        # Lock only the append for this snapshot.  A second sampler may still
        # capture its own timestamp during the interval, but cannot interleave
        # bytes with this writer or corrupt the evidence file.
        with _append_lock(output):
            with output.open("a", encoding="utf-8", newline="\n") as handle:
                for row in rows:
                    record = {
                        "timestamp": captured_at,
                        "sample_index": index,
                        "mode": mode,
                        **row,
                    }
                    if baseline_cpu_pct is not None:
                        record["baseline_cpu_pct"] = baseline_cpu_pct
                    handle.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")
                handle.flush()
        if index + 1 < samples:
            time.sleep(max(0, interval_ms) / 1000)
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--mode", choices=("baseline", "observe", "action"), required=True)
    parser.add_argument("--samples", type=int, default=10)
    parser.add_argument("--interval-ms", type=int, default=250)
    parser.add_argument("--baseline-cpu-pct", type=float)
    parser.add_argument("containers", nargs="*")
    args = parser.parse_args()
    return sample(args.output, mode=args.mode, samples=max(1, args.samples), interval_ms=args.interval_ms, containers=args.containers or None, baseline_cpu_pct=args.baseline_cpu_pct)


if __name__ == "__main__":
    raise SystemExit(main())
