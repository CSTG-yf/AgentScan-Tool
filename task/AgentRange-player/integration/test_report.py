import json

from report import build, to_markdown


def test_report_keeps_missing_runtime_evidence_explicit(tmp_path):
    (tmp_path / "integration" / "reports").mkdir(parents=True)
    (tmp_path / "bench" / "results").mkdir(parents=True)
    (tmp_path / "integration" / "reports" / "static-scan.json").write_text(
        json.dumps({"metrics": {"asset_coverage": 1.0, "risk_recall": 1.0}, "findings": []}), encoding="utf-8"
    )
    report = build(tmp_path)
    assert report["runtime"]["attack_chains"] == 0
    assert "Benchmark summary not generated" in to_markdown(report)
