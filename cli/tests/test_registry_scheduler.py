"""Persistent Registry scheduler behavior without network or scanner processes."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest

from defenseclaw.config import RegistrySource
from defenseclaw.registries.cache import source_dir
from defenseclaw.registries.scheduler import RegistryScheduler
from defenseclaw.registries.sync import SyncReport
from tests.helpers import make_temp_config


def _scheduler(tmp_path, *, outcome=None):
    cfg = make_temp_config(str(tmp_path))
    cfg.registries.sources = [RegistrySource(id="sample", kind="file", url="manifest.json", auto_sync=True)]
    now = [datetime(2026, 9, 29, tzinfo=timezone.utc)]
    calls = []

    def sync(_cfg, source):
        calls.append(source.id)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome or SyncReport(source_id=source.id)

    return RegistryScheduler(cfg.data_dir, lambda: cfg, sync, clock=lambda: now[0]), cfg, now, calls


def test_first_run_is_due_and_persisted_across_restart(tmp_path):
    scheduler, cfg, now, calls = _scheduler(tmp_path)
    assert scheduler.tick()[0]["status"] == "ok"
    assert calls == ["sample"]
    restarted = RegistryScheduler(cfg.data_dir, lambda: cfg, scheduler.sync, clock=lambda: now[0])
    assert restarted.tick()[0]["status"] == "scheduled"
    assert calls == ["sample"]
    now[0] += timedelta(hours=24)
    assert restarted.tick()[0]["status"] == "ok"
    assert calls == ["sample", "sample"]


def test_failures_back_off_and_recover(tmp_path):
    failed = SyncReport(source_id="sample", errors=["fetch: secret URL redacted"])
    scheduler, _cfg, now, calls = _scheduler(tmp_path, outcome=failed)
    first = scheduler.tick()[0]
    assert first["status"] == "error"
    assert first["last_result"] == "fetch"
    assert first["consecutive_failures"] == 1
    assert "secret" not in json.dumps(scheduler.state())
    assert scheduler.tick()[0]["status"] == "scheduled"
    now[0] += timedelta(seconds=60)
    assert scheduler.tick()[0]["consecutive_failures"] == 2
    assert calls == ["sample", "sample"]


def test_sync_exception_does_not_stop_other_sources(tmp_path):
    scheduler, cfg, _now, calls = _scheduler(tmp_path, outcome=RuntimeError("secret"))
    cfg.registries.sources.append(RegistrySource(id="other", kind="file", url="other.json", auto_sync=True))
    result = scheduler.tick()
    assert [item["status"] for item in result] == ["error", "error"]
    assert all(item["last_result"] == "RuntimeError" for item in result)
    assert calls == ["sample", "other"]
    assert "secret" not in json.dumps(scheduler.state())


def test_disabled_manual_and_invalid_interval_are_not_synced(tmp_path):
    scheduler, cfg, _now, calls = _scheduler(tmp_path)
    cfg.registries.sources[0].enabled = False
    cfg.registries.sources.append(RegistrySource(id="manual", auto_sync=False))
    cfg.registries.sources.append(RegistrySource(id="invalid", auto_sync=True, sync_interval_hours=0))
    assert scheduler.tick() == [{"source_id": "invalid", "status": "invalid_interval"}]
    assert calls == []


def test_manual_sync_timestamp_postpones_scheduled_run(tmp_path):
    scheduler, cfg, now, calls = _scheduler(tmp_path)
    cfg.registries.sources[0].last_sync = now[0].isoformat()
    cfg.registries.sources[0].last_status = "ok"
    assert scheduler.tick()[0]["status"] == "scheduled"
    assert calls == []


@pytest.mark.parametrize("content", ['[]', '{"schema_version":1,"sources":{"x":[]}}',
                                     '{"schema_version":1,"sources":{"x":{"consecutive_failures":-1}}}'])
def test_invalid_state_fails_closed(tmp_path, content):
    scheduler, _cfg, _now, calls = _scheduler(tmp_path)
    scheduler.state_path.write_text(content, encoding="utf-8")
    with pytest.raises(ValueError, match="invalid Registry scheduler"):
        scheduler.tick()
    assert calls == []


def test_source_id_cannot_escape_cache_on_windows_or_unix(tmp_path):
    with pytest.raises(ValueError, match="invalid source id"):
        source_dir(str(tmp_path), r"..\outside")
