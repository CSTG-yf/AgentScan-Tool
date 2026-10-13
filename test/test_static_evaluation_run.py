import json
from pathlib import Path

import pytest
import yaml

from integration.static_run import arena_hash, run_static_evaluation
from integration.evaluation_export import export_static


def test_source_scan_discovers_registered_tool_and_keeps_provenance(tmp_path):
    arena = tmp_path / "arena"
    (arena / "mcp" / "example").mkdir(parents=True)
    (arena / "docker-compose.yml").write_text("services:\n  mcp-example:\n    build: ./mcp\n    environment: {SERVER: example.server}\n")
    (arena / "mcp/example/server.py").write_text('from mcp_base.mcp_http import Tool, create_server\napp = create_server("example", [Tool("ping", "ping", {}, lambda: {})])\n')
    taxonomy = tmp_path / "taxonomy.yaml"
    taxonomy.write_text("rules: []\n")
    truth = tmp_path / "truth.yaml"
    truth.write_text(yaml.safe_dump(dict(arena_sha256=arena_hash(arena), asset_ids=["mcp.example", "tool.example.ping"], risk_pairs=[])))
    output = tmp_path / "output"
    result = run_static_evaluation(arena, truth, output, taxonomy)
    assert result["evaluation"]["asset"]["tp"] == 2
    assert result["evaluation"]["asset"]["fn"] == 0
    dashboard = result["dashboard"]
    assert dashboard["code_version"] and dashboard["config_hash"]
    assert dashboard["image_digest"] == "not_applicable:static_source_scan"
    missed = next(row for row in dashboard["instances"] if row["id"] == "tool.example.ping")
    assert missed["predicted"] is True and missed["asset_type"] == "tool"
    scan = json.loads((output / "static-scan.json").read_text())
    scan["assets"] = []
    (output / "static-scan.json").write_text(json.dumps(scan))
    with pytest.raises(ValueError, match="differs from execution manifest"):
        export_static(output / "static-scan.json", truth)


def test_source_scan_rejects_unreviewed_hash(tmp_path):
    arena = tmp_path / "arena"
    arena.mkdir()
    (arena / "docker-compose.yml").write_text("services: {}")
    truth = tmp_path / "truth.yaml"
    truth.write_text("arena_sha256: stale\nasset_ids: []\nrisk_pairs: []\n")
    with pytest.raises(ValueError, match="independently frozen"):
        run_static_evaluation(arena, truth, tmp_path / "out")
