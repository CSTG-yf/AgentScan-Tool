from runner import is_attack_scenario, summarize_records


def record(scenario, blocked, latency=10.0, error=""):
    return {
        "instance_id": scenario,
        "scenario": scenario,
        "target": "opspilot-app",
        "attack": is_attack_scenario(scenario),
        "blocked": blocked,
        "status_code": 403 if blocked else 200,
        "latency_ms": latency,
        "error": error,
    }


def test_summary_uses_instance_level_confusion_matrix():
    report = summarize_records(
        [
            record("C2-A", True, 20),
            record("C2-B", False, 40),
            record("B-OPS", False, 10),
            record("B-RD", True, 30),
        ]
    )
    assert report["counts"] == {"total": 4, "tp": 1, "fp": 1, "tn": 1, "fn": 1}
    assert report["metrics"]["precision"] == 0.5
    assert report["metrics"]["recall"] == 0.5
    assert report["metrics"]["fpr"] == 0.5
    assert report["metrics"]["fnr"] == 0.5
    assert report["metrics"]["latency_ms"]["p95"] == 40


def test_scenario_classification_does_not_depend_on_instance_id():
    assert is_attack_scenario("C1-A")
    assert is_attack_scenario("C2-D")
    assert not is_attack_scenario("B-SUP")
