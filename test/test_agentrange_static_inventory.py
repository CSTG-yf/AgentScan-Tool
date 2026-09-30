"""Asset discovery checks using a small arena with different service names."""

from pathlib import Path
import hashlib
import json
import tempfile
import unittest

import yaml

from integration.static_inventory import (
    DEFAULT_RANGE_ROOT,
    DEFAULT_TAXONOMY,
    asset_for_source,
    compose_service_lines,
    discover_assets,
    iter_sources,
    python_ast_matches,
    scan,
)
from integration.static_eval import DEFAULT_TRUTH, evaluate


class AgentRangeStaticInventoryTest(unittest.TestCase):
    def test_structured_config_holdout_ignores_comments_and_placeholders(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            arena = root / "arena"
            arena.mkdir()
            (arena / "docker-compose.yml").write_text("""
services:
  assistant-app:
    environment:
      LLM_BASE: http://model:8000/v1
      JWT_SECRET: weak-rotated-key
      OPSPILOT_PROPAGATION: service_account
      POSTGRES_PASSWORD: ${DB_PASSWORD}
  langflow-engine:
    image: langflowai/langflow:1.8
    build: ./langflow-engine
    environment:
      LANGFLOW_AUTO_LOGIN: true
      LANGFLOW_SKIP_AUTH_AUTO_LOGIN: false
""".lstrip(), encoding="utf-8")
            (arena / ".env.example").write_text("""
# JWT_SECRET=change-me-weak-secret
JWT_SECRET=dev-secret-123
POSTGRES_PASSWORD='other-password'
OPSPILOT_SERVICE_TOKEN=${SERVICE_TOKEN}
export LANGFLOW_AUTO_LOGIN=true
LANGFLOW_SKIP_AUTH_AUTO_LOGIN=false
LANGFLOW_SUPERUSER_PASSWORD=${LF_PASSWORD}
""".lstrip(), encoding="utf-8")
            app = arena / "assistant-app" / "api"
            app.mkdir(parents=True)
            (app / "app.py").write_text("# Agent entrypoint\n", encoding="utf-8")
            (app.parent / "settings.yaml").write_text("""
JWT_SECRET: ${JWT_SECRET}
POSTGRES_PASSWORD: ${DB_PASSWORD}
LANGFLOW_AUTO_LOGIN: false
note: "JWT_SECRET=change-me-weak-secret"
""".lstrip(), encoding="utf-8")
            framework = arena / "langflow-engine"
            framework.mkdir()
            (framework / "Dockerfile").write_text("""
# ENV LANGFLOW_SUPERUSER_PASSWORD=admin
FROM python:3.12-slim
ENV LANGFLOW_SUPERUSER_PASSWORD=separatepass
""".lstrip(), encoding="utf-8")

            scan_path = root / "scan.json"
            scan_path.write_text(
                json.dumps(scan(arena, taxonomy_path=DEFAULT_TAXONOMY)),
                encoding="utf-8",
            )
            digest = hashlib.sha256()
            for path in sorted(path for path in arena.rglob("*") if path.is_file()):
                digest.update(path.relative_to(arena).as_posix().encode("utf-8"))
                digest.update(hashlib.sha256(path.read_bytes()).hexdigest().encode("ascii"))
            truth_path = root / "holdout-truth.yaml"
            truth_path.write_text(yaml.safe_dump({
                "arena_sha256": digest.hexdigest(),
                "asset_ids": ["agent.assistant", "framework.langflow-engine"],
                "risk_pairs": [
                    ["AR-CONFIG-WEAK-JWT", "agent.assistant"],
                    ["AR-CONFIG-SERVICE-ACCOUNT", "agent.assistant"],
                    ["AR-CONFIG-PLAINTEXT-PASSWORD", "agent.assistant"],
                    ["AR-CONFIG-LANGFLOW-AUTOLOGIN", "framework.langflow-engine"],
                    ["AR-CONFIG-PLAINTEXT-PASSWORD", "framework.langflow-engine"],
                ],
            }), encoding="utf-8")
            result = evaluate(scan_path, truth_path, arena)
            self.assertEqual((result["asset"]["fp"], result["asset"]["fn"]), (0, 0))
            self.assertEqual((result["risk"]["fp"], result["risk"]["fn"]), (0, 0))
            findings = json.loads(scan_path.read_text(encoding="utf-8"))["findings"]
            self.assertIn(
                ("AR-CONFIG-LANGFLOW-AUTOLOGIN", "framework.langflow-engine", ".env.example"),
                {(row["rule_id"], row["asset_id"], row["source"]) for row in findings},
            )

    def test_mutated_layout_holdout_uses_independent_truth(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            arena = root / "arena"
            arena.mkdir()
            (arena / "docker-compose.yml").write_text("""
services:
  assistant:
    build: ./services/assistant
    environment:
      LLM_BASE: http://model-core:8000/v1
      MODEL_NAME: nova-v2
      MCP_NOTES: http://sync-worker:8000/mcp
      MCP_BAD: http://[broken
    ports: ["127.0.0.1:8100:8000", "8101:8001"]
  model-core:
    build: ./services/model
  helper:
    environment:
      LLM_BASE: http://model-core:8000/v1
  sync-worker:
    build: ./services/tools
    environment: {SERVER: sync.entrypoint}
  standalone-service:
    build: ./services/extra
    environment: {SERVER: extra.server}
  unrelated-worker:
    build: ./workers
    environment: {SERVER: worker.server}
""".lstrip(), encoding="utf-8")
            agent = arena / "services" / "assistant" / "api"
            agent.mkdir(parents=True)
            (agent / "app.py").write_text(
                'import os\nDEFAULT_MODEL = os.getenv("MODEL_NAME", "fallback")\n', encoding="utf-8",
            )
            (agent.parent / "unsafe.py").write_text(
                'import subprocess\ndef execute(cmd):\n    subprocess.run(cmd, shell=True)\n', encoding="utf-8",
            )
            model = arena / "services" / "model"
            model.mkdir(parents=True)
            (model / "app.py").write_text("# Model endpoint\n", encoding="utf-8")
            helper = arena / "helper" / "api"
            helper.mkdir(parents=True)
            (helper / "app.py").write_text(
                'import os\nDEFAULT_MODEL = os.environ.get("MODEL_ID", "aux-v1")\n', encoding="utf-8",
            )
            renamed_mcp = arena / "services" / "tools" / "sync"
            renamed_mcp.mkdir(parents=True)
            (renamed_mcp / "entrypoint.py").write_text(
                'import subprocess\ndef execute(cmd):\n    subprocess.run(cmd, shell=True)\n', encoding="utf-8",
            )
            standalone_mcp = arena / "services" / "extra" / "extra"
            standalone_mcp.mkdir(parents=True)
            (standalone_mcp / "server.py").write_text(
                'from mcp.server.fastmcp import FastMCP\napp = FastMCP("standalone")\n', encoding="utf-8",
            )
            unrelated = arena / "workers" / "worker"
            unrelated.mkdir(parents=True)
            (unrelated / "server.py").write_text("def serve():\n    return 1\n", encoding="utf-8")
            nested_skill = arena / "skills" / "group" / "audit"
            nested_skill.mkdir(parents=True)
            (nested_skill / "SKILL.md").write_text("# Audit\n", encoding="utf-8")

            report = scan(arena, taxonomy_path=DEFAULT_TAXONOMY)
            report_path = root / "scan.json"
            report_path.write_text(json.dumps(report), encoding="utf-8")

            digest = hashlib.sha256()
            for path in sorted(path for path in arena.rglob("*") if path.is_file()):
                digest.update(path.relative_to(arena).as_posix().encode("utf-8"))
                digest.update(hashlib.sha256(path.read_bytes()).hexdigest().encode("ascii"))
            truth_path = root / "holdout-truth.yaml"
            truth_path.write_text(yaml.safe_dump({
                "arena_sha256": digest.hexdigest(),
                "asset_ids": [
                    "agent.assistant", "model.nova-v2", "agent.helper", "model.aux-v1",
                    "mcp.sync-worker", "mcp.standalone-service",
                    "skill.group.audit", "port.assistant.8100", "port.assistant.8101",
                ],
                "risk_pairs": [
                    ["AR-STATIC-SHELL-TRUE", "mcp.sync-worker"],
                    ["AR-STATIC-SHELL-TRUE", "agent.assistant"],
                ],
            }), encoding="utf-8")
            evaluation = evaluate(report_path, truth_path, arena)
            self.assertEqual((evaluation["asset"]["fp"], evaluation["asset"]["fn"]), (0, 0))
            self.assertEqual((evaluation["risk"]["fp"], evaluation["risk"]["fn"]), (0, 0))
            self.assertNotIn("mcp.unrelated-worker", {asset["id"] for asset in report["assets"]})
            self.assertEqual(discover_assets(arena)["agent.assistant"]["source"], "services/assistant/api/app.py")
            self.assertEqual(discover_assets(arena)["model.nova-v2"]["source"], "services/model/app.py")
            self.assertIn(renamed_mcp / "entrypoint.py", set(iter_sources(arena, discover_assets(arena))))
            edges = {(row["from"], row["relation"], row["to"]) for row in report["asset_edges"]}
            self.assertIn(("agent.assistant", "uses", "model.nova-v2"), edges)
            self.assertIn(("agent.assistant", "calls", "mcp.sync-worker"), edges)
            compose_path = arena / "docker-compose.yml"
            compose_path.write_text(
                compose_path.read_text(encoding="utf-8").replace(
                    "LLM_BASE: http://model-core:8000/v1", "LLM_BASE: http://[broken",
                ), encoding="utf-8",
            )
            self.assertIn("agent.assistant", discover_assets(arena))

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
    build: ./llm-stub
    ports: ["8000:8000"]
  lookup-service:
    build: ./mcp
    environment: {SERVER: lookup.server}
  unrelated-worker:
    build: ./workers
    environment: {SERVER: worker.server}
  solo-agent:
    environment: {LLM_BASE: "http://llm-stub:8000/v1"}
  probe-service:
    image: acme/mcp-probe:1
    environment: {SERVER: probe.server}
networks:
  internal-net: {}
""".lstrip(),
                encoding="utf-8",
            )
            app = root / "atlas-app" / "api"
            app.mkdir(parents=True)
            (app / "app.py").write_text('DEFAULT_MODEL = "atlas-v1"\n', encoding="utf-8")
            solo_app = root / "solo-agent" / "api"
            solo_app.mkdir(parents=True)
            (solo_app / "app.py").write_text("# standalone agent\n", encoding="utf-8")
            (solo_app / "rules.py").write_text("subprocess.run(user_cmd, shell = True)\n", encoding="utf-8")
            model_app = root / "llm-stub" / "llm_stub"
            model_app.mkdir(parents=True)
            (model_app / "app.py").write_text("# model endpoint\n", encoding="utf-8")
            skill = root / "skills" / "triage"
            skill.mkdir(parents=True)
            (skill / "SKILL.md").write_text("# Triage\n", encoding="utf-8")

            discovered = discover_assets(root)
            self.assertTrue({
                "agent.atlas", "model.atlas-v1", "mcp.search", "database.orders",
                "framework.langflow", "skill.triage", "network.internal",
                "mcp.lookup-service",
                "agent.solo-agent", "mcp.probe-service",
                "port.atlas", "port.postgres", "port.llm-stub",
            }.issubset(discovered))
            self.assertEqual(discovered["model.atlas-v1"]["source"], "llm-stub/llm_stub/app.py")
            self.assertEqual(
                asset_for_source("atlas-app/api/app.py", list(discovered.values())),
                "agent.atlas",
            )
            self.assertNotIn("mcp.unrelated-worker", discovered)
            self.assertIn(solo_app / "rules.py", set(iter_sources(root, discovered)))
            self.assertEqual(
                asset_for_source("docker-compose.yml", [], service="lookup-service", discovered=discovered),
                "mcp.lookup-service",
            )

            lines = compose_service_lines(root / "docker-compose.yml")
            self.assertEqual(lines[9], "postgres-orders")
            self.assertEqual(
                asset_for_source("docker-compose.yml", [], service=lines[9]),
                "database.orders",
            )

            taxonomy = root / "taxonomy.yaml"
            taxonomy.write_text(yaml.safe_dump({
                "rules": [{
                    "id": "AR-STATIC-SHELL-TRUE", "title": "Shell execution", "category": "command_execution",
                    "severity": "CRITICAL", "confidence": 0.96, "patterns": ["shell=True"],
                }],
            }), encoding="utf-8")
            result = scan(root, taxonomy_path=taxonomy)
            self.assertIn(
                ("AR-STATIC-SHELL-TRUE", "agent.solo-agent"),
                {(finding["rule_id"], finding["asset_id"]) for finding in result["findings"]},
            )

    def test_scan_does_not_use_labeled_contract(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            taxonomy = yaml.safe_load(DEFAULT_TAXONOMY.read_text(encoding="utf-8"))
            taxonomy["acceptance"] = {
                "required_rule_assets": [["invented-rule", "invented-asset"]],
                "benign_controls": ["mcp.notes-sync"],
            }
            taxonomy_path = root / "taxonomy.yaml"
            taxonomy_path.write_text(yaml.safe_dump(taxonomy), encoding="utf-8")
            result = scan(DEFAULT_RANGE_ROOT, taxonomy_path=taxonomy_path)
            control = scan(DEFAULT_RANGE_ROOT)
            self.assertEqual(result["assets"], control["assets"])
            self.assertEqual(result["asset_edges"], control["asset_edges"])
            self.assertEqual(result["findings"], control["findings"])
            self.assertNotIn("missing_required_risks", result)
            self.assertNotIn("asset_observations", result)
            scan_path = root / "scan.json"
            scan_path.write_text(json.dumps(result), encoding="utf-8")
            evaluation = evaluate(
                scan_path,
                DEFAULT_TRUTH,
                DEFAULT_RANGE_ROOT,
            )
            self.assertEqual(evaluation["arena_sha256"], "bcd51ef41b2bfd2871a06e03e6835d26c41e45436e86121c722981b06dcc5d5b")
            self.assertEqual((evaluation["asset"]["tp"], evaluation["risk"]["tp"]), (27, 13))
            self.assertEqual((evaluation["asset"]["fp"], evaluation["risk"]["fp"]), (0, 0))


if __name__ == "__main__":
    unittest.main()
