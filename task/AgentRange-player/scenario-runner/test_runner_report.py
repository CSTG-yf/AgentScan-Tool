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
    assert report["counts"] == {"total": 4, "valid": 4, "invalid": 0, "tp": 1, "fp": 1, "tn": 1, "fn": 1}
    assert report["metrics"]["precision"] == 0.5
    assert report["metrics"]["recall"] == 0.5
    assert report["metrics"]["fpr"] == 0.5
    assert report["metrics"]["fnr"] == 0.5
    assert report["metrics"]["latency_ms"]["p95"] == 40
    assert report["metrics"]["normal_success_rate"] == 0.5


def test_scenario_classification_does_not_depend_on_instance_id():
    assert is_attack_scenario("C1-A")
    assert is_attack_scenario("C2-D")
    assert not is_attack_scenario("B-SUP")


def test_infrastructure_error_is_reported_as_invalid():
    report = summarize_records([record("B-OPS", False, error="ConnectError")])
    assert report["counts"]["invalid"] == 1
    assert report["counts"]["tn"] == 0
    assert report["metrics"]["normal_success_rate"] == 0.0


def test_summary_uses_detected_for_observe_metrics():
    item = record("C2-D", False)
    item["detected"] = True
    report = summarize_records([item])
    assert report["counts"]["tp"] == 1
    assert report["counts"]["fn"] == 0
    assert report["by_scenario"]["C2-D"]["blocked"] == 0
    assert report["by_scenario"]["C2-D"]["detected"] == 1


def test_fail_closed_style_error_is_invalid_not_tp():
    item = record("C2-D", True, error="defenseclaw_block_without_action_mode")
    report = summarize_records([item])
    assert report["counts"]["invalid"] == 1
    assert report["counts"]["tp"] == 0
