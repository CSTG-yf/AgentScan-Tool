from pathlib import Path

from build_dashboard import build


def test_dashboard_covers_competition_metrics_and_scenarios():
    data = build()
    assert len(data["scorecard"]) == 7
    assert len(data["scenarios"]) == 7
    assert data["traceability"]["total"] == 12
    assert {item["name"] for item in data["scorecard"]} >= {
        "资产盘点准确率",
        "风险识别准确率",
        "恶意实例 Recall",
        "正常实例 FPR",
        "阻断响应 p95",
        "DefenseClaw 增量 CPU",
        "正常业务中断",
    }


def test_action_results_are_reported_with_explicit_gap():
    data = build()
    assert data["modes"]["action"]["available"] is True
    assert data["modes"]["action"]["valid"] == 5200
    assert data["modes"]["action"]["recall"] == 0.65
    action_metrics = {item["name"]: item for item in data["scorecard"]}
    recall = next(item for item in action_metrics.values() if "Recall" in item["name"])
    fpr = next(item for item in action_metrics.values() if "FPR" in item["name"])
    p95 = next(item for item in action_metrics.values() if "p95" in item["name"])
    cpu = next(item for item in action_metrics.values() if "CPU" in item["name"])
    assert recall["status"] == "fail"
    assert fpr["status"] == "pass"
    assert p95["status"] == "pass"
    assert cpu["status"] == "pass"


def test_static_page_has_required_landmarks():
    html = (Path(__file__).with_name("index.html")).read_text(encoding="utf-8")
    for landmark in ('id="scorecard"', 'id="scenarios"', 'id="evidence"', 'id="metricGrid"'):
        assert landmark in html
    assert "data.js" in html
    assert "app.js" in html
