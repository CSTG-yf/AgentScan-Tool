from static_inventory import scan


def test_static_inventory_matches_frozen_denominator(range_root):
    report = scan(range_root)
    assert report["metrics"]["asset_coverage"] == 1.0
    assert report["metrics"]["risk_recall"] == 1.0
    assert report["missing_required_risks"] == []


def test_benign_password_and_threat_intel_controls_are_not_high_risk(range_root):
    report = scan(range_root)
    assert report["benign_control_violations"] == []
