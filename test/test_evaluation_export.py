"""Contract tests for post-run evidence import, without running an arena."""
import hashlib
import json
from pathlib import Path

import pytest

from integration.evaluation_export import export_runtime, export_static


def write_json(path, value):
    path.write_text(json.dumps(value))


def write_jsonl(path, rows):
    path.write_text("".join(json.dumps(row) + "\n" for row in rows))


@pytest.fixture
def recorded_run(tmp_path):
    write_jsonl(tmp_path / "gt.jsonl", [{"instance_id": "attack", "label": "malicious", "scenario_id": "C1-A", "expected_target": "framework.langflow"}, {"instance_id": "normal", "label": "benign", "scenario_id": "normal", "expected_target": "agent.opspilot"}])
    write_jsonl(tmp_path / "public-corpus.jsonl", [{"instance_id": "attack", "input": "public"}, {"instance_id": "normal", "input": "public"}])
    write_json(tmp_path / "run.json", {"mode": "action", "git_commit": "recorded", "total": 2, "arena_sha256": "arena", "ground_truth_sha256": hashlib.sha256((tmp_path / "gt.jsonl").read_bytes()).hexdigest(), "public_corpus_sha256": hashlib.sha256((tmp_path / "public-corpus.jsonl").read_bytes()).hexdigest()})
    write_json(tmp_path / "replay-process.json", {"started_at": "2026-10-09T00:00:00Z", "finished_at": "2026-10-09T00:00:04Z", "returncode": 0})
    write_jsonl(tmp_path / "observations.jsonl", [dict(instance_id="attack", decision="block", valid=True, timeout=False, inspect_unavailable_count=0, inspect_latency_ms=20, e2e_latency_ms=30, detector_block_evidence=[{"enforced": True}], side_effect_reached=False, side_effect_probe_status="complete", side_effect_probe_refs=[{"probe": "target", "matches": 0}]), dict(instance_id="normal", decision="allow", valid=True, timeout=False, inspect_unavailable_count=0, business_success=True, inspect_latency_ms=10, e2e_latency_ms=20)])
    write_jsonl(tmp_path / "runtime-events.jsonl", [dict(instance_id="attack", timestamp="2026-10-09T00:00:01Z", severity="CRITICAL"), dict(instance_id="normal", timestamp="2026-10-09T00:00:02Z", severity="NONE")])
    return tmp_path


def test_runtime_export_preserves_receipts_independent_truth_and_missing_metadata(recorded_run):
    result = export_runtime(recorded_run)
    labels = json.loads(result["artifacts"][0]["content"])
    assert labels == {"runtime": {"attack": True, "normal": False}}
    attack = next(row for row in result["instances"] if row["id"] == "attack")
    assert attack["response_status"] == "executed"
    assert attack["actually_blocked"] is True and attack["side_effect_occurred"] is False
    assert attack["evidence"]["response"] and attack["evidence"]["side_effect"]
    assert result["config_hash"] == result["image_digest"] == ""
    assert "未记录" in result["notes"][-1]
    for artifact in result["artifacts"]:
        assert hashlib.sha256(artifact["content"].encode()).hexdigest() == artifact["sha256"]
    assert all(series["expected_samples"] == 2 and series["complete"] for series in result["series"])


def test_runtime_export_does_not_invent_a_block_receipt_or_side_effect_probe(recorded_run):
    rows = [json.loads(line) for line in (recorded_run / "observations.jsonl").read_text().splitlines()]
    rows[0].pop("detector_block_evidence")
    rows[0].pop("side_effect_probe_refs")
    rows[0]["side_effect_probe_status"] = "missing"
    write_jsonl(recorded_run / "observations.jsonl", rows)
    attack = export_runtime(recorded_run)["instances"][0]
    assert attack["actually_blocked"] is None
    assert attack["side_effect_occurred"] is None
    assert "response" not in attack["evidence"] and "side_effect" not in attack["evidence"]


def test_runtime_export_rejects_changed_dataset_or_truth(recorded_run):
    (recorded_run / "public-corpus.jsonl").write_text("{}\n")
    with pytest.raises(ValueError, match="public corpus hash"):
        export_runtime(recorded_run)


def test_static_export_retains_misses_and_unexpected_assets(tmp_path):
    write_json(tmp_path / "static-scan.json", {"assets": [{"id": "agent.found", "type": "agent"}, {"id": "plugin.unexpected", "type": "plugin"}], "findings": []})
    write_json(tmp_path / "static-eval.json", {"arena_sha256": "new-arena"})
    truth = tmp_path / "truth.yaml"
    truth.write_text("arena_sha256: frozen-arena\nasset_ids: [agent.found, skill.missing]\nrisk_pairs: [[RISK, skill.missing]]\n")
    result = export_static(tmp_path / "static-scan.json", truth)
    assert result["static_truth"]["dataset_hash"] != result["static_dataset_hash"]
    found = {row["id"]: row for row in result["instances"]}
    assert found["skill.missing"]["predicted"] is False
    assert found["plugin.unexpected"]["predicted"] is True
    assert found["RISK:skill.missing"]["predicted"] is False
