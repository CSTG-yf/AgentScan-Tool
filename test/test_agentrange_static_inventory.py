"""Asset discovery checks using a small arena with different service names."""

from pathlib import Path
import hashlib
import json
import tempfile
import unittest

from integration.static_inventory import asset_for_source, compose_service_lines, discover_assets, python_ast_matches
from integration.static_eval import evaluate


class AgentRangeStaticInventoryTest(unittest.TestCase):
    def test_python_risks_follow_syntax_not_comments_or_spacing(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "server.py"
            path.write_text(
                "# hidden=True; shell=True; with open(path)\n"
                "description = 'shell=True'\n"
                "Tool('internal', hidden = True)\n"
                "def execute(command):\n"
                "    subprocess.run(command, shell = True)\n"
                "def read_any(user_path):\n"
                "    return open(user_path).read()\n",
                encoding="utf-8",
            )
            self.assertEqual(python_ast_matches(path), {
                "AR-STATIC-HIDDEN-TOOL": {3},
                "AR-STATIC-SHELL-TRUE": {5},
                "AR-STATIC-ARBITRARY-FILE": {7},
            })

    def test_static_eval_counts_false_positives_and_misses(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            arena = root / "arena"
            arena.mkdir()
            digest = hashlib.sha256().hexdigest()
            truth = root / "truth.yaml"
            truth.write_text(
                f"arena_sha256: {digest}\nasset_ids: [agent.good, skill.missing]\n"
                "risk_pairs:\n  - [RULE-A, agent.good]\n  - [RULE-B, skill.missing]\n",
                encoding="utf-8",
            )
            scan = root / "scan.json"
            scan.write_text(json.dumps({
                "range_root": str(arena),
                "assets": [{"id": "agent.good"}, {"id": "agent.extra"}],
                "findings": [
                    {"rule_id": "RULE-A", "asset_id": "agent.good"},
                    {"rule_id": "RULE-X", "asset_id": "agent.extra"},
                ],
            }), encoding="utf-8")
            result = evaluate(scan, truth, arena)
            self.assertEqual(result["asset"]["tp"], 1)
            self.assertEqual(result["asset"]["fp"], 1)
            self.assertEqual(result["asset"]["fn"], 1)
            self.assertEqual(result["risk"]["precision"], 0.5)
            self.assertFalse(result["acceptance"]["asset_precision_gte_0_99"])

    def test_discovers_assets_from_compose_and_skill_sources(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "docker-compose.yml").write_text(
                """
services:
  atlas-app:
    environment:
      LLM_BASE: http://llm-stub:8000/v1
      MCP_SEARCH: http://mcp-search:8000/mcp
    ports: ["8100:8000"]
  mcp-search:
    environment: {SERVER: search.server}
  postgres-orders:
    image: postgres:16-alpine
    ports: ["55432:5432"]
  langflow:
    image: langflowai/langflow:1.8
  llm-stub:
    ports: ["8000:8000"]
networks:
  internal-net: {}
""".lstrip(),
                encoding="utf-8",
            )
            app = root / "atlas-app" / "api"
            app.mkdir(parents=True)
            (app / "app.py").write_text('DEFAULT_MODEL = "atlas-v1"\n', encoding="utf-8")
            skill = root / "skills" / "triage"
            skill.mkdir(parents=True)
            (skill / "SKILL.md").write_text("# Triage\n", encoding="utf-8")

            discovered = discover_assets(root)
            self.assertTrue({
                "agent.atlas", "model.atlas-v1", "mcp.search", "database.orders",
                "framework.langflow", "skill.triage", "network.internal",
                "port.atlas", "port.postgres", "port.llm-stub",
            }.issubset(discovered))
            self.assertEqual(discovered["model.atlas-v1"]["source"], "atlas-app/api/app.py")

            lines = compose_service_lines(root / "docker-compose.yml")
            self.assertEqual(lines[9], "postgres-orders")
            self.assertEqual(
                asset_for_source("docker-compose.yml", [], service=lines[9]),
                "database.orders",
            )


if __name__ == "__main__":
    unittest.main()
