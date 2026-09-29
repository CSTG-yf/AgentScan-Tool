"""Persistent, source-scoped scheduler for Registry ingest.

The process is deliberately independent of the desktop window. Operators run
``defenseclaw registry scheduler run`` under their service manager; each tick
reloads config so source changes take effect without restarting the daemon.
"""

from __future__ import annotations

import json
import os
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from defenseclaw.config import Config, RegistrySource, _lock_file_exclusive, _unlock_file
from defenseclaw.registries.cache import _atomic_write, cache_root
from defenseclaw.registries.sync import SyncReport


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _parse_time(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed.astimezone(timezone.utc) if parsed.tzinfo else None


def _failure_kind(report: SyncReport) -> str:
    if report.ok():
        return "ok"
    first = report.errors[0] if report.errors else "unknown"
    return first.split(":", 1)[0].strip().replace(" ", "_")[:50] or "sync_failed"


class RegistryScheduler:
    def __init__(
        self,
        data_dir: str,
        load_config: Callable[[], Config],
        sync: Callable[[Config, RegistrySource], SyncReport],
        *,
        clock: Callable[[], datetime] = _now,
    ) -> None:
        self.data_dir = data_dir
        self.load_config = load_config
        self.sync = sync
        self.clock = clock
        self.root = cache_root(data_dir)
        self.state_path = self.root / "schedule.json"
        self.lock_path = self.root / ".schedule.lock"

    def state(self) -> dict[str, Any]:
        if not self.state_path.is_file():
            return {"schema_version": 1, "sources": {}}
        data = json.loads(self.state_path.read_text(encoding="utf-8"))
        if not isinstance(data, dict) or data.get("schema_version") != 1 or not isinstance(data.get("sources"), dict):
            raise ValueError("invalid Registry scheduler state; refusing automatic sync")
        for entry in data["sources"].values():
            if not isinstance(entry, dict):
                raise ValueError("invalid Registry scheduler source state; refusing automatic sync")
            failures = entry.get("consecutive_failures", 0)
            if not isinstance(failures, int) or isinstance(failures, bool) or failures < 0:
                raise ValueError("invalid Registry scheduler failure count; refusing automatic sync")
        return data

    def tick(self) -> list[dict[str, Any]]:
        """Run due sources once; persist each outcome before moving on."""
        with self.lock_path.open("a+b") as lock_file:
            if os.name != "nt":
                os.chmod(self.lock_path, 0o600)
            _lock_file_exclusive(lock_file)
            try:
                return self._tick_locked()
            finally:
                _unlock_file(lock_file)

    def _tick_locked(self) -> list[dict[str, Any]]:
        cfg = self.load_config()
        state = self.state()
        now = self.clock().astimezone(timezone.utc)
        results: list[dict[str, Any]] = []
        for source in cfg.registries.sources:
            if not source.enabled or not source.auto_sync:
                continue
            if source.sync_interval_hours <= 0:
                results.append({"source_id": source.id, "status": "invalid_interval"})
                continue
            previous = state["sources"].get(source.id, {})
            last_attempt = _parse_time(previous.get("last_attempt_at"))
            config_attempt = _parse_time(source.last_sync)
            failures = previous.get("consecutive_failures", 0)
            if config_attempt and (last_attempt is None or config_attempt > last_attempt):
                last_attempt = config_attempt
                failures = 0 if source.last_status == "ok" else 1
            interval = timedelta(hours=source.sync_interval_hours)
            backoff = timedelta(seconds=min(60 * (2 ** min(failures - 1, 10)), int(interval.total_seconds()))) if failures else interval
            due_at = last_attempt + backoff if last_attempt else now
            if now < due_at:
                results.append({"source_id": source.id, "status": "scheduled", "next_run_at": due_at.isoformat()})
                continue
            try:
                report = self.sync(cfg, source)
                ok = report.ok()
                result_kind = _failure_kind(report)
            except Exception as exc:  # noqa: BLE001 - persist failure and retry later
                ok = False
                result_kind = type(exc).__name__
            failures = 0 if ok else failures + 1
            delay = interval if ok else timedelta(seconds=min(60 * (2 ** min(failures - 1, 10)), int(interval.total_seconds())))
            entry = {
                "last_attempt_at": now.isoformat(),
                "next_run_at": (now + delay).isoformat(),
                "consecutive_failures": failures,
                "last_result": result_kind,
            }
            state["sources"][source.id] = entry
            _atomic_write(self.state_path, (json.dumps(state, indent=2, sort_keys=True) + "\n").encode("utf-8"))
            results.append({"source_id": source.id, "status": "ok" if ok else "error", **entry})
        return results
