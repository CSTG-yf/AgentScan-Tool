from rule_contract import verify


def test_all_rules_have_attack_two_benign_and_meet_performance(range_root):
    report = verify(range_root / "integration" / "runtime_rules.yaml")
    assert report["passed"], report
    assert all(len(item["benign_matches"]) >= 2 for item in report["results"])
