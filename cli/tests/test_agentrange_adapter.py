from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner
from defenseclaw.agentrange_adapter import (
    build_adapter_bundle,
    discover_agentrange,
    write_adapter_bundle,
)
from defenseclaw.main import cli


def _write_minimal_range(root: Path) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    compose = root / "docker-compose.yml"
    compose.write_text(
        """
services:
  llm-stub:
    image: llm-stub
    networks: [opspilot-net]
    ports: ["8000:8000"]
  opspilot-app:
    image: opspilot
    environment:
      LLM_BASE: http://llm-stub:8000/v1
      LANGFLOW_BASE: http://langflow:7860
      MCP_CUSTOMER_DB: http://mcp-customer-db:8000/mcp
      MCP_SHELL_RUNNER: http://mcp-shell-runner:8000/mcp
    networks: [opspilot-net]
    ports: ["8100:8000"]
  langflow:
    image: langflow
    environment:
      OPENAI_API_BASE: http://llm-stub:8000/v1
    networks: [opspilot-net]
    ports: ["7860:7860"]
  mcp-customer-db:
    image: mcp
    networks: [opspilot-net]
  mcp-shell-runner:
    image: mcp
    networks: [opspilot-net, egress-net]
networks:
  opspilot-net:
    driver: bridge
  egress-net:
    driver: bridge
""".lstrip(),
        encoding="utf-8",
    )
    return compose


def test_discover_agentrange_compose_assets(tmp_path: Path) -> None:
    compose = _write_minimal_range(tmp_path)

    discovery = discover_agentrange(tmp_path)

    assert discovery.compose_path == str(compose.resolve())
    assert discovery.opspilot_service == "opspilot-app"
    assert discovery.langflow_service == "langflow"
    assert discovery.llm_base == "http://llm-stub:8000/v1"
    assert discovery.llm_target_base == "http://llm-stub:8000"
    assert discovery.llm_proxy_base == "http://defenseclaw-llm-proxy:8000/v1"
    assert [route.env_key for route in discovery.mcp_routes] == ["MCP_CUSTOMER_DB", "MCP_SHELL_RUNNER"]
    assert discovery.egress_services == ["mcp-shell-runner"]


def test_write_bundle_is_external_and_rewrites_runtime_routes(tmp_path: Path) -> None:
    compose = _write_minimal_range(tmp_path / "range")
    original = compose.read_text(encoding="utf-8")
    output_dir = tmp_path / "defenseclaw-out"

    bundle = build_adapter_bundle(tmp_path / "range", output_dir)
    write_adapter_bundle(bundle)

    assert compose.read_text(encoding="utf-8") == original

    override = Path(bundle.override_path).read_text(encoding="utf-8")
    assert "defenseclaw-opspilot-ingress" in override
    assert "defenseclaw-llm-proxy" in override
    assert "defenseclaw-mcp-proxy" in override
    assert "defenseclaw-langflow-ingress" in override
    assert "LLM_BASE: http://defenseclaw-llm-proxy:8000/v1" in override
    assert "MCP_CUSTOMER_DB: http://defenseclaw-mcp-proxy:8000/mcp-customer-db/mcp" in override
    assert "LANGFLOW_BASE: http://defenseclaw-langflow-ingress:7860" in override
    assert "ports: !reset []" in override

    plan = json.loads(Path(bundle.plan_path).read_text(encoding="utf-8"))
    assert plan["non_invasive"] is True
    assert plan["source"]["range_root"] == "../range"
    assert plan["source"]["compose_path"] == "../range/docker-compose.yml"
    assert not Path(plan["source"]["sidecar_source"]).is_absolute()
    assert "portable_range_root" not in plan["source"]
    assert {route["kind"] for route in plan["routes"]} == {"app", "llm", "mcp", "langflow"}
    assert "session_id" in plan["event_model"]
    assert "tool_name" in plan["event_model"]


def test_refuses_to_write_bundle_inside_range_root(tmp_path: Path) -> None:
    _write_minimal_range(tmp_path)
    bundle = build_adapter_bundle(tmp_path, tmp_path / ".defenseclaw" / "agentrange")

    try:
        write_adapter_bundle(bundle)
    except ValueError as exc:
        assert "refusing to write" in str(exc)
    else:
        raise AssertionError("expected adapter output inside range root to be rejected")


def test_cli_agentrange_adapt_works_without_init(tmp_path: Path) -> None:
    _write_minimal_range(tmp_path / "range")
    output_dir = tmp_path / "out"

    runner = CliRunner()
    result = runner.invoke(
        cli,
        [
            "agentrange",
            "adapt",
            "--range-root",
            str(tmp_path / "range"),
            "--output-dir",
            str(output_dir),
        ],
    )

    assert result.exit_code == 0, result.output
    assert "AgentRange adapter bundle generated" in result.output
    assert (output_dir / "docker-compose.defenseclaw.override.yml").is_file()
