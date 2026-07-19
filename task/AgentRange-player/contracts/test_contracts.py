import json
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
CONTRACTS = ROOT / "contracts"


def test_asset_denominator_matches_range_sources():
    contract = yaml.safe_load((CONTRACTS / "assets.yaml").read_text(encoding="utf-8"))
    assets = contract["assets"]
    by_type = {}
    for asset in assets:
        by_type.setdefault(asset["type"], []).append(asset)
        assert (ROOT / asset["source"]).exists(), asset
    expected = contract["denominator"]
    aliases = {"supply_chain_framework": "supply_chain_frameworks", "database": "databases", "mcp_server": "mcp_servers", "skill": "skills", "network": "networks", "host_port": "host_ports", "agent": "agents", "model": "models"}
    for asset_type, denominator_name in aliases.items():
        assert len(by_type.get(asset_type, [])) == expected[denominator_name]


def test_scenario_contract_is_exact_and_forbids_answer_inputs():
    matrix = yaml.safe_load((CONTRACTS / "scenario-matrix.yaml").read_text(encoding="utf-8"))
    assert set(matrix["scenarios"]) == {"C1-A", "C1-B", "C2-A", "C2-B", "C2-C", "C2-D", "normal"}
    forbidden = " ".join(matrix["forbidden_detection_inputs"])
    assert "/admin/trajectories" in forbidden
    assert "scenario_id" in forbidden


def test_ground_truth_examples_cover_every_scenario():
    rows = [json.loads(line) for line in (CONTRACTS / "examples.jsonl").read_text(encoding="utf-8").splitlines()]
    assert len(rows) == 7
    assert {row["scenario_id"] for row in rows} == {"C1-A", "C1-B", "C2-A", "C2-B", "C2-C", "C2-D", "normal"}
    assert len({row["instance_id"] for row in rows}) == len(rows)
