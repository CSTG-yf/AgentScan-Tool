from pathlib import Path

from requirements_contract import evaluate


def test_plan_requirements_map_to_implementation_files():
    repo_root = Path(__file__).resolve().parents[3]
    report = evaluate(repo_root)
    assert len(report["requirements"]) == 12
    assert report["counts"]["not-implemented"] == 0
    assert {row["id"] for row in report["requirements"]} == {
        "FR-01", "FR-02", "FR-03", "FR-04", "FR-05", "FR-06",
        "FR-07", "FR-08", "FR-09", "FR-10", "NFR-01", "NFR-02",
    }
