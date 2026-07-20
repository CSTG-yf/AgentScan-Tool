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


def test_missing_action_results_are_not_reported_as_passed():
    data = build()
    assert data["modes"]["action"]["available"] is False
    action_metrics = {item["name"]: item for item in data["scorecard"]}
    for name in ("恶意实例 Recall", "正常实例 FPR", "阻断响应 p95", "DefenseClaw 增量 CPU"):
        assert action_metrics[name]["status"] == "wait"
        assert action_metrics[name]["actual"] == "待实测"


def test_static_page_has_required_landmarks():
    html = (Path(__file__).with_name("index.html")).read_text(encoding="utf-8")
    for landmark in ('id="scorecard"', 'id="scenarios"', 'id="evidence"', 'id="metricGrid"'):
        assert landmark in html
    assert "data.js" in html
    assert "app.js" in html
