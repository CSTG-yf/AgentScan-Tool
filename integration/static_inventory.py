"""Deterministic AgentRange asset and configuration risk scanner."""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import re
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlsplit

import yaml


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_RANGE_ROOT = PROJECT_ROOT / "task" / "AgentRange-player-full"
DEFAULT_CONTRACTS_DIR = PROJECT_ROOT / "integration" / "agentrange_contracts"
DEFAULT_TAXONOMY = PROJECT_ROOT / "integration" / "risk_taxonomy.yaml"
DEFAULT_OUTPUT = PROJECT_ROOT / "integration" / "reports" / "static-scan.json"

TEXT_SUFFIXES = {".py", ".md", ".yaml", ".yml", ".env", ".example", ".json", ".toml"}
PYTHON_AST_RULES = {
    "AR-STATIC-HIDDEN-TOOL",
    "AR-STATIC-SHELL-TRUE",
    "AR-STATIC-ARBITRARY-FILE",
}
CONFIG_RULES = {
    "AR-CONFIG-WEAK-JWT",
    "AR-CONFIG-SERVICE-ACCOUNT",
    "AR-CONFIG-PLAINTEXT-PASSWORD",
    "AR-CONFIG-LANGFLOW-AUTOLOGIN",
}


def load_yaml(path: Path) -> dict:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def python_ast_matches(path: Path) -> dict[str, set[int]]:
    """Find executable Python constructs without matching comments or strings."""
    matches: dict[str, set[int]] = {rule: set() for rule in PYTHON_AST_RULES}
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"))
    except (SyntaxError, UnicodeError):
        return matches

    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            parameters = {arg.arg for arg in node.args.posonlyargs + node.args.args + node.args.kwonlyargs}
            for child in ast.walk(node):
                if (isinstance(child, ast.Call) and isinstance(child.func, ast.Name)
                        and child.func.id == "open" and child.args
                        and isinstance(child.args[0], ast.Name) and child.args[0].id in parameters):
                    matches["AR-STATIC-ARBITRARY-FILE"].add(child.lineno)
        if not isinstance(node, ast.Call):
            continue
        name = node.func.id if isinstance(node.func, ast.Name) else node.func.attr if isinstance(node.func, ast.Attribute) else ""
        keywords = {keyword.arg: keyword.value for keyword in node.keywords if keyword.arg}
        if name == "Tool" and isinstance(keywords.get("hidden"), ast.Constant) and keywords["hidden"].value is True:
            matches["AR-STATIC-HIDDEN-TOOL"].add(node.lineno)
        if (name in {"run", "Popen", "call", "check_call", "check_output"}
                and isinstance(keywords.get("shell"), ast.Constant) and keywords["shell"].value is True):
            matches["AR-STATIC-SHELL-TRUE"].add(node.lineno)
    return matches


def _mcp_module(path: Path) -> bool:
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"))
    except (SyntaxError, UnicodeError, OSError):
        return False
    mcp_import = any(
        isinstance(node, ast.ImportFrom) and "mcp" in (node.module or "").casefold()
        or isinstance(node, ast.Import) and any("mcp" in alias.name.casefold() for alias in node.names)
        for node in ast.walk(tree)
    )
    calls = {
        node.func.id if isinstance(node.func, ast.Name) else node.func.attr
        for node in ast.walk(tree) if isinstance(node, ast.Call)
        and isinstance(node.func, (ast.Name, ast.Attribute))
    }
    return "FastMCP" in calls or (mcp_import and "create_server" in calls)


def _hostname(value: str) -> str:
    try:
        return urlsplit(value).hostname or ""
    except ValueError:
        return ""


def iter_sources(root: Path, discovered: dict[str, dict[str, str]]):
    scan_roots = {"docker-compose.yml", ".env.example"}
    for asset in discovered.values():
        source = asset["source"].replace("\\", "/")
        if "/" in source:
            scan_roots.add(source.split("/", 1)[0])
    for relative in sorted(scan_roots):
        target = root / relative
        candidates = target.rglob("*") if target.is_dir() else [target]
        for path in candidates:
            if not path.is_file() or "__pycache__" in path.parts:
                continue
            if path.suffix.lower() in TEXT_SUFFIXES or path.name in {"Dockerfile", ".env.example", "SKILL.md"}:
                yield path


def _environment(service: dict) -> dict[str, str]:
    value = service.get("environment") or {}
    if isinstance(value, dict):
        return {str(key): str(item) for key, item in value.items()}
    if isinstance(value, list):
        return {
            str(item).split("=", 1)[0]: str(item).split("=", 1)[1]
            for item in value if isinstance(item, str) and "=" in item
        }
    return {}


def _default_model(path: Path, env: dict[str, str]) -> str | None:
    if not path.is_file():
        return None
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"))
    except (SyntaxError, UnicodeError):
        return None
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(
            isinstance(target, ast.Name) and target.id == "DEFAULT_MODEL" for target in node.targets
        ):
            if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                return node.value.value
            value = node.value
            if not isinstance(value, ast.Call) or not value.args or not isinstance(value.args[0], ast.Constant):
                continue
            key = value.args[0].value
            if not isinstance(key, str):
                continue
            getenv = isinstance(value.func, ast.Attribute) and (
                (isinstance(value.func.value, ast.Name) and value.func.value.id == "os" and value.func.attr == "getenv")
                or (isinstance(value.func.value, ast.Attribute) and isinstance(value.func.value.value, ast.Name)
                    and value.func.value.value.id == "os" and value.func.value.attr == "environ"
                    and value.func.attr == "get")
            )
            if not getenv:
                continue
            configured = env.get(key, "")
            if configured.startswith("${") and configured.endswith("}") and ":-" in configured:
                configured = configured[2:-1].split(":-", 1)[1]
            if configured and "$" not in configured:
                return configured
            if len(value.args) > 1 and isinstance(value.args[1], ast.Constant) and isinstance(value.args[1].value, str):
                return value.args[1].value
    return None


def discover_assets(root: Path) -> dict[str, dict[str, str]]:
    """Discover typed assets from deployment and Skill metadata."""
    compose_path = root / "docker-compose.yml"
    compose = load_yaml(compose_path)
    services = compose.get("services") or {}
    discovered: dict[str, dict[str, str]] = {}
    mcp_references = {
        hostname
        for service in services.values() if isinstance(service, dict)
        for key, value in _environment(service).items() if key.startswith("MCP_")
        if (hostname := _hostname(value))
    }

    def add(asset_id: str, kind: str, name: str, source: str, service_name: str = "") -> None:
        discovered[asset_id] = {"id": asset_id, "type": kind, "name": name, "source": source}
        if service_name:
            discovered[asset_id]["service_name"] = service_name

    for service_name, service in services.items():
        if not isinstance(service, dict):
            continue
        env = _environment(service)
        image = str(service.get("image") or "").lower()
        build = service.get("build") or ""
        build_context = build if isinstance(build, str) else str(build.get("context") or "") if isinstance(build, dict) else ""
        service_source = "docker-compose.yml"
        context = str(build_context).removeprefix("./")
        module = str(env.get("SERVER") or "").split(":", 1)[0].replace(".", "/")
        candidate = f"{context}/{module}.py" if context and module else ""
        module_source_exists = bool(candidate and (root / candidate).is_file())
        if "SERVER" in env and (
            service_name.startswith("mcp-")
            or Path(build_context).name.startswith("mcp")
            or image.rsplit("/", 1)[-1].startswith("mcp-")
            or service_name in mcp_references
            or (module_source_exists and _mcp_module(root / candidate))
        ):
            name = service_name.removeprefix("mcp-")
            context = context or "mcp"
            candidate = f"{context}/{module}.py"
            source = candidate if (root / candidate).is_file() else service_source
            add(f"mcp.{name}", "mcp_server", name, source, service_name)
        elif "LLM_BASE" in env:
            name = service_name.removesuffix("-app")
            candidates = [f"{service_name}/api/app.py"]
            if context:
                candidates.append(f"{context}/api/app.py")
            source = next((item for item in candidates if (root / item).is_file()), service_source)
            add(f"agent.{name}", "agent", name, source, service_name)
            model = _default_model(root / source, env)
            if model:
                model_service_name = _hostname(env["LLM_BASE"])
                model_service = services.get(model_service_name) or {}
                model_build = (model_service.get("build") or "") if isinstance(model_service, dict) else ""
                if isinstance(model_build, str):
                    model_context = model_build
                elif isinstance(model_build, dict):
                    model_context = str(model_build.get("context") or "")
                else:
                    model_context = ""
                model_root = model_context.removeprefix("./")
                model_candidates = (
                    f"{model_root}/{model_service_name.replace('-', '_')}/app.py",
                    f"{model_root}/api/app.py", f"{model_root}/app.py",
                )
                model_source = next(
                    (item for item in model_candidates if model_root and (root / item).is_file()), source,
                )
                add(f"model.{model}", "model", model, model_source)
        elif "langflow" in service_name.lower() or "langflow" in image:
            candidate = f"{str(build_context).removeprefix('./')}/Dockerfile"
            source = candidate if build_context and (root / candidate).is_file() else service_source
            add(f"framework.{service_name}", "supply_chain_framework", service_name, source, service_name)
        elif image.startswith(("postgres:", "mysql:", "mariadb:")):
            name = service_name.split("-", 1)[-1]
            add(f"database.{name}", "database", service_name, service_source, service_name)

        port_name = service_name.removesuffix("-app")
        if image.startswith("postgres:"):
            port_name = "postgres"
        published_ports = []
        for port in service.get("ports") or []:
            parts = port.rsplit(":", 2) if isinstance(port, str) else []
            host_port = parts[-2] if len(parts) >= 2 else str(port.get("published") or "") if isinstance(port, dict) else ""
            if host_port:
                published_ports.append(host_port)
        for host_port in published_ports:
            asset_id = f"port.{port_name}"
            if len(published_ports) > 1:
                asset_id += f".{host_port}"
            add(asset_id, "host_port", host_port, service_source)

    for network_name in (compose.get("networks") or {}):
        name = str(network_name).removesuffix("-net")
        add(f"network.{name}", "network", str(network_name), "docker-compose.yml")
    for skill_file in sorted((root / "skills").rglob("SKILL.md")):
        skill_path = skill_file.parent.relative_to(root / "skills")
        name = skill_file.parent.name
        add(f"skill.{'.'.join(skill_path.parts)}", "skill", name, skill_file.relative_to(root).as_posix())
    return discovered


def compose_service_lines(path: Path) -> dict[int, str]:
    """Map Compose source lines to service names using YAML node locations."""
    root = yaml.compose(path.read_text(encoding="utf-8"))
    if not isinstance(root, yaml.MappingNode):
        return {}
    for key, value in root.value:
        if isinstance(key, yaml.ScalarNode) and key.value == "services" and isinstance(value, yaml.MappingNode):
            lines: dict[int, str] = {}
            for service_key, service_value in value.value:
                if isinstance(service_key, yaml.ScalarNode):
                    for line in range(service_key.start_mark.line + 1, service_value.end_mark.line + 2):
                        lines[line] = service_key.value
            return lines
    return {}


def _assignment(value: str) -> tuple[str, str] | None:
    if "=" not in value:
        return None
    key, raw = value.split("=", 1)
    key = key.strip()
    if not re.fullmatch(r"[A-Za-z_][A-Za-z_0-9]*", key):
        return None
    raw = raw.strip()
    if raw.startswith(("'", '"')) and raw.endswith(raw[0]):
        raw = raw[1:-1]
    else:
        raw = raw.split(" #", 1)[0].strip()
    return key, raw


def _config_entries(path: Path):
    if path.suffix.lower() in {".yaml", ".yml"}:
        try:
            document = yaml.compose(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, yaml.YAMLError):
            return

        def walk(node):
            if not isinstance(node, yaml.MappingNode):
                return
            for key, value in node.value:
                if not isinstance(key, yaml.ScalarNode):
                    continue
                if isinstance(value, yaml.ScalarNode):
                    yield key.start_mark.line + 1, key.value, value.value
                elif key.value == "environment" and isinstance(value, yaml.SequenceNode):
                    for item in value.value:
                        if isinstance(item, yaml.ScalarNode) and (entry := _assignment(item.value)):
                            yield item.start_mark.line + 1, *entry
                yield from walk(value)

        if document is not None:
            yield from walk(document)
    elif path.name == "Dockerfile" or path.suffix.lower() in {".env", ".example"}:
        for line_number, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if path.name == "Dockerfile":
                if not stripped.startswith("ENV "):
                    continue
                stripped = stripped[4:].strip()
            elif stripped.startswith("export "):
                stripped = stripped[7:].strip()
            if entry := _assignment(stripped):
                yield line_number, *entry


def _config_rule_ids(key: str, value: str) -> set[str]:
    value = value.strip()
    if not value or "$" in value or "{{" in value or (value.startswith("<") and value.endswith(">")):
        return set()
    lowered = value.casefold()
    if key == "JWT_SECRET":
        obvious = re.search(r"(?:^|[-_])(?:change|changeme|default|dev|demo|test|example|weak)(?:[-_]|$)", lowered)
        if len(value) < 16 or len(value) <= 40 and obvious:
            return {"AR-CONFIG-WEAK-JWT"}
    if key == "OPSPILOT_PROPAGATION" and lowered.replace("_", "-") == "service-account":
        return {"AR-CONFIG-SERVICE-ACCOUNT"}
    if key == "OPSPILOT_SERVICE_TOKEN" and any(marker in lowered for marker in ("root", "all-access", "admin")):
        return {"AR-CONFIG-SERVICE-ACCOUNT"}
    if key in {"POSTGRES_PASSWORD", "LANGFLOW_SUPERUSER_PASSWORD"}:
        return {"AR-CONFIG-PLAINTEXT-PASSWORD"}
    if key in {"LANGFLOW_AUTO_LOGIN", "LANGFLOW_SKIP_AUTH_AUTO_LOGIN"} and lowered in {"true", "yes", "on", "1"}:
        return {"AR-CONFIG-LANGFLOW-AUTOLOGIN"}
    return set()


def asset_for_source(source: str, assets: list[dict], *, service: str = "", discovered: dict | None = None) -> str:
    if service:
        if discovered:
            for asset in discovered.values():
                if asset.get("service_name") == service:
                    return asset["id"]
        if service.startswith("mcp-"):
            return "mcp." + service.removeprefix("mcp-")
        if service == "langflow":
            return "framework.langflow"
        if service.endswith("-app"):
            return "agent." + service.removesuffix("-app")
        if service.startswith("postgres-"):
            return "database." + service.split("-", 1)[-1]
        return "service." + service
    normalized = source.replace("\\", "/")
    exact = {}
    for asset in assets:
        if asset["source"] != "docker-compose.yml":
            exact.setdefault(asset["source"].replace("\\", "/"), asset["id"])
    if normalized in exact:
        return exact[normalized]
    for asset in sorted(assets, key=lambda item: len(item["source"]), reverse=True):
        asset_source = asset["source"].replace("\\", "/")
        if "/" in asset_source and normalized.startswith(asset_source.rsplit("/", 1)[0] + "/"):
            return asset["id"]
    source_roots: dict[str, set[str]] = {}
    for asset in assets:
        source_parts = asset["source"].replace("\\", "/").split("/")
        if asset["type"] == "agent" and len(source_parts) >= 3:
            source_roots.setdefault("/".join(source_parts[:-2]), set()).add(asset["id"])
    for source_root in sorted(source_roots, key=len, reverse=True):
        if normalized.startswith(source_root + "/") and len(source_roots[source_root]) == 1:
            return next(iter(source_roots[source_root]))
    if normalized in {".env.example", "docker-compose.yml"}:
        agents = [asset["id"] for asset in assets if asset["type"] == "agent"]
        if len(agents) == 1:
            return agents[0]
    return "unmapped." + normalized.replace("/", ".")


def scan(
    range_root: Path,
    contracts_dir: Path = DEFAULT_CONTRACTS_DIR,
    taxonomy_path: Path = DEFAULT_TAXONOMY,
) -> dict:
    contract = load_yaml(contracts_dir / "assets.yaml")
    taxonomy = load_yaml(taxonomy_path)
    assets = contract["assets"]
    discovered = discover_assets(range_root)
    compose_lines = compose_service_lines(range_root / "docker-compose.yml")
    findings = []
    seen = set()
    for path in iter_sources(range_root, discovered):
        relative = path.relative_to(range_root).as_posix()
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        semantic_matches = python_ast_matches(path) if path.suffix == ".py" else {}
        config_matches: dict[str, dict[int, str]] = {rule_id: {} for rule_id in CONFIG_RULES}
        for line_number, key, value in _config_entries(path):
            for rule_id in _config_rule_ids(key, value):
                config_matches[rule_id][line_number] = key
        for rule in taxonomy["rules"]:
            if rule["id"] in semantic_matches:
                candidates = ((line_number, lines[line_number - 1], "") for line_number in sorted(semantic_matches[rule["id"]]))
            elif rule["id"] in CONFIG_RULES:
                candidates = ((line_number, lines[line_number - 1], config_matches[rule["id"]][line_number])
                              for line_number in sorted(config_matches[rule["id"]]))
            else:
                candidates = (
                    (line_number, line, "")
                    for pattern in rule["patterns"]
                    for line_number, line in enumerate(lines, 1)
                    if pattern.casefold() in line.casefold()
                )
            for line_number, line, config_key in candidates:
                service = compose_lines.get(line_number, "") if relative == "docker-compose.yml" else ""
                asset_id = asset_for_source(relative, list(discovered.values()), service=service, discovered=discovered)
                if path.name.endswith(".env.example") and config_key.startswith("LANGFLOW_"):
                    frameworks = [asset["id"] for asset in discovered.values()
                                  if asset["type"] == "supply_chain_framework" and "langflow" in asset["name"].casefold()]
                    if len(frameworks) == 1:
                        asset_id = frameworks[0]
                identity = (rule["id"], asset_id, relative, line_number)
                if identity in seen:
                    continue
                seen.add(identity)
                findings.append(
                    {
                        "finding_id": hashlib.sha256("|".join(map(str, identity)).encode()).hexdigest()[:16],
                        "rule_id": rule["id"],
                        "title": rule["title"],
                        "category": rule["category"],
                        "severity": rule["severity"],
                        "confidence": rule["confidence"],
                        "asset_id": asset_id,
                        "source": relative,
                        "line": line_number,
                        "evidence": line.strip()[:240],
                    }
                )

    expected_ids = {asset["id"] for asset in assets}
    unexpected_assets = [discovered[asset_id] for asset_id in sorted(set(discovered) - expected_ids)]
    existing_assets = [
        {**discovered[asset_id], "observed_source": discovered[asset_id]["source"]}
        for asset_id in sorted(discovered)
    ]
    asset_observations = [
        {
            "asset_id": asset["id"],
            "type": asset.get("type", ""),
            "source": asset["source"],
            "source_exists": (range_root / asset["source"]).exists(),
            "observed_by_source_probe": asset["id"] in discovered,
            "observed_source": discovered.get(asset["id"], {}).get("source"),
        }
        for asset in assets
    ]
    required = {tuple(item) for item in taxonomy["acceptance"]["required_rule_assets"]}
    detected = {(item["rule_id"], item["asset_id"]) for item in findings}
    benign = set(taxonomy["acceptance"]["benign_controls"])
    high_risk_benign = [item for item in findings if item["asset_id"] in benign and item["severity"] in {"HIGH", "CRITICAL"}]
    return {
        "schema_version": 1,
        "generated_at": datetime.now(UTC).isoformat(),
        "range_root": str(range_root),
        "contracts_dir": str(contracts_dir),
        "assets": existing_assets,
        "asset_edges": contract["edges"],
        "findings": findings,
        "metrics": {
            "asset_expected": len(assets),
            "asset_found": len(discovered),
            "asset_coverage": round(len(expected_ids & set(discovered)) / len(assets), 6) if assets else 1.0,
            "contract_asset_coverage": round(len(expected_ids & set(discovered)) / len(assets), 6) if assets else 1.0,
            "asset_precision": None,
            "asset_recall": None,
            "asset_metric_status": "requires_independent_asset_ground_truth",
            "required_risks": len(required),
            "required_risks_detected": len(required & detected),
            "risk_recall": round(len(required & detected) / len(required), 6) if required else 1.0,
            "risk_precision": None,
            "risk_metric_status": "contract_rule_coverage_only",
            "high_risk_benign_findings": len(high_risk_benign),
        },
        "asset_observations": asset_observations,
        "unexpected_assets": unexpected_assets,
        "missing_required_risks": sorted([list(item) for item in required - detected]),
        "benign_control_violations": high_risk_benign,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--range-root", type=Path, default=DEFAULT_RANGE_ROOT)
    parser.add_argument("--contracts-dir", type=Path, default=DEFAULT_CONTRACTS_DIR)
    parser.add_argument("--taxonomy", type=Path, default=DEFAULT_TAXONOMY)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    report = scan(args.range_root.resolve(), args.contracts_dir.resolve(), args.taxonomy.resolve())
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({"output": str(args.output), **report["metrics"]}, ensure_ascii=False, indent=2))
    return 0 if not report["missing_required_risks"] and not report["benign_control_violations"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
