import json

from benchmark import summarize


def mode_report(recall=1.0, fpr=0.0, success=1.0, p95=20.0):
    return {
        "counts": {"total": 4, "valid": 4, "invalid": 0, "tp": 1, "fp": 0, "tn": 3, "fn": 0},
        "metrics": {"recall": recall, "fpr": fpr, "normal_success_rate": success},
        "inspect_latency_ms": {"p95": p95},
        "resources": {"after": {"rows": [{"CPUPerc": "2.0%"}]}},
    }


def test_three_mode_summary_and_acceptance(tmp_path):
    for mode in ("baseline", "observe", "action"):
        (tmp_path / f"{mode}.json").write_text(json.dumps(mode_report()), encoding="utf-8")
    output = tmp_path / "summary.json"
    report = summarize(tmp_path, output)
    assert report["missing_modes"] == []
    assert all(report["acceptance"].values())
