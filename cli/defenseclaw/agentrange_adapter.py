# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

"""AgentRange non-invasive adapter bundle generation.

This module turns an untouched AgentRange checkout into a Docker Compose
overlay that routes runtime traffic through DefenseClaw-owned sidecars. The
original range stays a traffic source; all inspection code lives in this
package.
"""

from __future__ import annotations

import inspect as py_inspect
import json
import os
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import yaml

from defenseclaw import agentrange_sidecar

DEFAULT_GATEWAY_BASE = "http://host.docker.internal:18970"
DEFAULT_OUTPUT_SUBDIR = Path(".defenseclaw") / "agentrange"
DEFAULT_FAIL_MODE = "open"
DEFAULT_INSPECT_TIMEOUT_MS = 250

OPSPILOT_SERVICE_CANDIDATES = ("opspilot-app", "opspilot")
LANGFLOW_SERVICE_CANDIDATES = ("langflow",)
LLM_ENV_KEYS = ("LLM_BASE", "OPENAI_API_BASE", "OPENAI_BASE_URL")

EVENT_MODEL_FIELDS = [
    "instance_id",
    "session_id",
    "trace_id",
    "stage",
    "source",
    "destination",
    "actor",
    "tenant",
    "prompt",
    "model",
    "tool_name",
    "mcp_server",
    "request_body",
    "response_body",
    "decision",
    "severity",
    "reason",
    "latency_ms",
    "raw_ref",
]


class ComposeResetList(list):
    """Render a Docker Compose ``!reset []`` sequence."""


class ComposeDumper(yaml.SafeDumper):
    """Safe dumper extended with Docker Compose override tags."""

    def ignore_aliases(self, data: Any) -> bool:
        return True


def _represent_reset_list(dumper: yaml.Dumper, data: ComposeResetList) -> yaml.Node:
    return dumper.represent_sequence("!reset", list(data), flow_style=True)


ComposeDumper.add_representer(ComposeResetList, _represent_reset_list)


@dataclass(frozen=True)
class PortBinding:
    published: str
    target: str
    protocol: str = "tcp"
    host_ip: str = ""

    def compose_value(self) -> str:
        target = self.target
        if self.protocol and self.protocol != "tcp":
            target = f"{target}/{self.protocol}"
        if self.host_ip:
            return f"{self.host_ip}:{self.published}:{target}"
        return f"{self.published}:{target}"


@dataclass(frozen=True)
class MCPRoute:
    env_key: str
    original_url: str
    target_service: str
    target_base: str
    target_path: str
    proxy_url: str


@dataclass(frozen=True)
class AgentRangeDiscovery:
    range_root: str
    compose_path: str
    opspilot_service: str
    langflow_service: str | None
    llm_base: str | None
    llm_target_base: str | None
    llm_proxy_base: str | None
    mcp_routes: list[MCPRoute]
    networks: list[str]
    opspilot_ports: list[PortBinding]
    langflow_ports: list[PortBinding]
    egress_services: list[str]

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["mcp_routes"] = [asdict(route) for route in self.mcp_routes]
        data["opspilot_ports"] = [asdict(port) for port in self.opspilot_ports]
        data["langflow_ports"] = [asdict(port) for port in self.langflow_ports]
        return data


@dataclass(frozen=True)
class AdapterBundle:
    output_dir: str
    override_path: str
    plan_path: str
    readme_path: str
    discovery: AgentRangeDiscovery
    plan: dict[str, Any]
    compose_text: str
    readme_text: str


def discover_agentrange(range_root: str | Path, compose_file: str = "docker-compose.yml") -> AgentRangeDiscovery:
    """Inspect an AgentRange checkout without modifying it."""

    root = Path(range_root).expanduser().resolve()
    compose_path = (root / compose_file).resolve()
    if not compose_path.is_file():
        raise FileNotFoundError(f"AgentRange compose file not found: {compose_path}")

    compose = _load_yaml_mapping(compose_path)
    services = compose.get("services")
    if not isinstance(services, dict) or not services:
        raise ValueError(f"{compose_path} does not define any compose services")

    opspilot_service = _find_opspilot_service(services)
    if not opspilot_service:
        raise ValueError("could not find OpsPilot service; expected opspilot-app or a service with LLM_BASE/MCP_* env")

    langflow_service = _find_named_service(services, LANGFLOW_SERVICE_CANDIDATES)
    ops_env = _env_to_dict(services[opspilot_service].get("environment"))
    langflow_env = _env_to_dict(services.get(langflow_service, {}).get("environment")) if langflow_service else {}

    llm_base = _first_env_value(ops_env, LLM_ENV_KEYS) or _first_env_value(langflow_env, LLM_ENV_KEYS)
    llm_target_base = _url_origin(llm_base) if llm_base else None
    llm_proxy_base = _sidecar_llm_base(llm_base) if llm_base else None

    networks = _discover_networks(services)
    mcp_routes = _build_mcp_routes(ops_env)

    return AgentRangeDiscovery(
        range_root=str(root),
        compose_path=str(compose_path),
        opspilot_service=opspilot_service,
        langflow_service=langflow_service,
        llm_base=llm_base,
        llm_target_base=llm_target_base,
        llm_proxy_base=llm_proxy_base,
        mcp_routes=mcp_routes,
        networks=networks,
        opspilot_ports=_parse_ports(
            services[opspilot_service].get("ports"),
            default_target="8000",
            default_published="8100",
        ),
        langflow_ports=_parse_ports(
            services.get(langflow_service, {}).get("ports") if langflow_service else None,
            default_target="7860",
            default_published="7860",
        ),
        egress_services=_services_on_network(services, "egress-net"),
    )


def build_adapter_bundle(
    range_root: str | Path,
    output_dir: str | Path | None = None,
    *,
    gateway_base: str = DEFAULT_GATEWAY_BASE,
    mode: str = "observe",
    fail_mode: str = DEFAULT_FAIL_MODE,
    inspect_timeout_ms: int = DEFAULT_INSPECT_TIMEOUT_MS,
) -> AdapterBundle:
    """Build generated file contents for a non-invasive AgentRange adapter."""

    discovery = discover_agentrange(range_root)
    out_dir = Path(output_dir) if output_dir is not None else Path.cwd() / DEFAULT_OUTPUT_SUBDIR
    out_dir = out_dir.expanduser().resolve()
    sidecar_path = Path(py_inspect.getfile(agentrange_sidecar)).resolve()
    plan = _build_plan(discovery, sidecar_path, gateway_base, mode, fail_mode, inspect_timeout_ms)
    plan["source"]["portable_range_root"] = _portable_path(Path(discovery.range_root), base_dir=out_dir)
    plan["source"]["portable_compose_path"] = _portable_path(Path(discovery.compose_path), base_dir=out_dir)
    plan["source"]["portable_sidecar_source"] = _portable_path(sidecar_path, base_dir=out_dir)
    compose_text = _dump_compose(_compose_override(plan))
    public_plan = _public_plan(plan)
    readme_text = _render_readme(public_plan, out_dir)

    return AdapterBundle(
        output_dir=str(out_dir),
        override_path=str(out_dir / "docker-compose.defenseclaw.override.yml"),
        plan_path=str(out_dir / "agentrange-adapter-plan.json"),
        readme_path=str(out_dir / "README.md"),
        discovery=discovery,
        plan=public_plan,
        compose_text=compose_text,
        readme_text=readme_text,
    )


def write_adapter_bundle(
    bundle: AdapterBundle,
    *,
    force: bool = False,
    allow_range_output: bool = False,
) -> AdapterBundle:
    """Write the adapter bundle while keeping the original range immutable."""

    out_dir = Path(bundle.output_dir).resolve()
    range_root = Path(bundle.discovery.range_root).resolve()
    if not allow_range_output and _is_relative_to(out_dir, range_root):
        raise ValueError(
            "refusing to write AgentRange adapter output inside the range root; "
            "choose a DefenseClaw-side output directory"
        )

    files = {
        Path(bundle.override_path): bundle.compose_text,
        Path(bundle.plan_path): json.dumps(bundle.plan, indent=2, ensure_ascii=False) + "\n",
        Path(bundle.readme_path): bundle.readme_text,
    }
    existing = [path for path in files if path.exists()]
    if existing and not force:
        names = ", ".join(str(path) for path in existing)
        raise FileExistsError(f"adapter output already exists: {names}; pass --force to overwrite")

    out_dir.mkdir(parents=True, exist_ok=True)
    for path, text in files.items():
        path.write_text(text, encoding="utf-8")
    return bundle


def _load_yaml_mapping(path: Path) -> dict[str, Any]:
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(data, dict):
        raise ValueError(f"{path} is not a YAML mapping")
    return data


def _find_named_service(services: dict[str, Any], candidates: tuple[str, ...]) -> str | None:
    by_lower = {str(name).lower(): str(name) for name in services}
    for candidate in candidates:
        if candidate in by_lower:
            return by_lower[candidate]
    return None


def _find_opspilot_service(services: dict[str, Any]) -> str | None:
    named = _find_named_service(services, OPSPILOT_SERVICE_CANDIDATES)
    if named:
        return named
    for name, service in services.items():
        env = _env_to_dict(service.get("environment") if isinstance(service, dict) else None)
        if any(key in env for key in LLM_ENV_KEYS) and any(key.startswith("MCP_") for key in env):
            return str(name)
    return None


def _env_to_dict(env: Any) -> dict[str, str]:
    if env is None:
        return {}
    if isinstance(env, dict):
        return {str(key): "" if value is None else str(value) for key, value in env.items()}
    if isinstance(env, list):
        out: dict[str, str] = {}
        for item in env:
            if not isinstance(item, str):
                continue
            if "=" in item:
                key, value = item.split("=", 1)
                out[key] = value
            else:
                out[item] = f"${{{item}}}"
        return out
    return {}


def _first_env_value(env: dict[str, str], keys: tuple[str, ...]) -> str | None:
    for key in keys:
        value = env.get(key)
        if value:
            return value
    return None


def _url_origin(raw_url: str | None) -> str | None:
    if not raw_url:
        return None
    parsed = urlsplit(raw_url)
    if not parsed.scheme or not parsed.netloc:
        return raw_url.rstrip("/")
    return f"{parsed.scheme}://{parsed.netloc}"


def _url_path(raw_url: str | None, default: str = "") -> str:
    if not raw_url:
        return default
    parsed = urlsplit(raw_url)
    path = parsed.path.rstrip("/")
    return path or default


def _sidecar_llm_base(llm_base: str | None) -> str | None:
    if not llm_base:
        return None
    suffix = _url_path(llm_base)
    return f"http://defenseclaw-llm-proxy:8000{suffix}"


def _build_mcp_routes(env: dict[str, str]) -> list[MCPRoute]:
    routes: list[MCPRoute] = []
    for key in sorted(k for k in env if k.startswith("MCP_")):
        original = env[key]
        parsed = urlsplit(original)
        host = parsed.hostname or _mcp_env_to_service(key)
        scheme = parsed.scheme or "http"
        port = f":{parsed.port}" if parsed.port else ""
        target_base = f"{scheme}://{host}{port}"
        target_path = parsed.path or "/mcp"
        proxy_url = f"http://defenseclaw-mcp-proxy:8000/{host}{target_path}"
        routes.append(
            MCPRoute(
                env_key=key,
                original_url=original,
                target_service=host,
                target_base=target_base,
                target_path=target_path,
                proxy_url=proxy_url,
            )
        )
    return routes


def _mcp_env_to_service(key: str) -> str:
    name = key.removeprefix("MCP_").lower().replace("_", "-")
    return f"mcp-{name}"


def _discover_networks(services: dict[str, Any]) -> list[str]:
    networks: set[str] = set()
    for service in services.values():
        for name in _service_networks(service if isinstance(service, dict) else {}):
            networks.add(name)
    return sorted(networks) or ["default"]


def _service_networks(service: dict[str, Any]) -> list[str]:
    raw = service.get("networks")
    if isinstance(raw, list):
        return [str(item) for item in raw]
    if isinstance(raw, dict):
        return [str(item) for item in raw.keys()]
    return []


def _services_on_network(services: dict[str, Any], network: str) -> list[str]:
    out = []
    for name, service in services.items():
        if network in _service_networks(service if isinstance(service, dict) else {}):
            out.append(str(name))
    return sorted(out)


def _parse_ports(raw: Any, *, default_target: str, default_published: str) -> list[PortBinding]:
    if not raw:
        return [PortBinding(published=default_published, target=default_target)]
    out: list[PortBinding] = []
    if not isinstance(raw, list):
        return [PortBinding(published=default_published, target=default_target)]
    for item in raw:
        parsed = _parse_port_binding(item)
        if parsed:
            out.append(parsed)
    return out or [PortBinding(published=default_published, target=default_target)]


def _parse_port_binding(item: Any) -> PortBinding | None:
    if isinstance(item, dict):
        target = str(item.get("target") or "")
        published = str(item.get("published") or "")
        if not target:
            return None
        return PortBinding(
            published=published or target,
            target=target,
            protocol=str(item.get("protocol") or "tcp"),
            host_ip=str(item.get("host_ip") or item.get("host_ip") or ""),
        )
    if not isinstance(item, str):
        return None
    value = item.strip().strip('"').strip("'")
    protocol = "tcp"
    if "/" in value:
        value, protocol = value.rsplit("/", 1)
    parts = value.split(":")
    if len(parts) == 1:
        return PortBinding(published=parts[0], target=parts[0], protocol=protocol)
    if len(parts) == 2:
        return PortBinding(published=parts[0], target=parts[1], protocol=protocol)
    return PortBinding(host_ip=":".join(parts[:-2]), published=parts[-2], target=parts[-1], protocol=protocol)


def _build_plan(
    discovery: AgentRangeDiscovery,
    sidecar_path: Path,
    gateway_base: str,
    mode: str,
    fail_mode: str,
    inspect_timeout_ms: int,
) -> dict[str, Any]:
    mcp_targets = {route.target_service: route.target_base for route in discovery.mcp_routes}
    opspilot_env: dict[str, str] = {
        "DEFENSECLAW_CONNECTOR": "agentrange",
        "DEFENSECLAW_ADAPTER": "external-sidecar",
    }
    if discovery.llm_proxy_base:
        opspilot_env["LLM_BASE"] = discovery.llm_proxy_base
    if discovery.langflow_service:
        opspilot_env["LANGFLOW_BASE"] = "http://defenseclaw-langflow-ingress:7860"
    for route in discovery.mcp_routes:
        opspilot_env[route.env_key] = route.proxy_url

    plan = {
        "adapter": "agentrange",
        "non_invasive": True,
        "source": {
            "range_root": discovery.range_root,
            "compose_path": discovery.compose_path,
            "sidecar_source": str(sidecar_path),
        },
        "gateway": {
            "base_url": gateway_base.rstrip("/"),
            "token_env": "DEFENSECLAW_GATEWAY_TOKEN",
            "mode": mode,
            "fail_mode": fail_mode,
            "inspect_timeout_ms": inspect_timeout_ms,
        },
        "services": {
            "opspilot": discovery.opspilot_service,
            "langflow": discovery.langflow_service,
            "llm_target_base": discovery.llm_target_base,
            "mcp_targets": mcp_targets,
            "egress_services": discovery.egress_services,
        },
        "rewrites": {
            "opspilot_environment": opspilot_env,
            "langflow_environment": {"OPENAI_API_BASE": discovery.llm_proxy_base} if discovery.llm_proxy_base else {},
        },
        "ingress": {
            "opspilot": {
                "service": "defenseclaw-opspilot-ingress",
                "target": f"http://{discovery.opspilot_service}:8000",
                "ports": [asdict(port) for port in discovery.opspilot_ports],
            },
            "langflow": {
                "service": "defenseclaw-langflow-ingress",
                "target": "http://langflow:7860",
                "ports": [asdict(port) for port in discovery.langflow_ports],
            }
            if discovery.langflow_service
            else None,
        },
        "routes": [
            {"kind": "app", "from": "host", "via": "defenseclaw-opspilot-ingress", "to": discovery.opspilot_service},
            {
                "kind": "llm",
                "from": discovery.opspilot_service,
                "via": "defenseclaw-llm-proxy",
                "to": discovery.llm_target_base,
            },
            *[
                {
                    "kind": "mcp",
                    "env": route.env_key,
                    "from": discovery.opspilot_service,
                    "via": "defenseclaw-mcp-proxy",
                    "to": route.target_service,
                    "path": route.target_path,
                }
                for route in discovery.mcp_routes
            ],
        ],
        "event_model": EVENT_MODEL_FIELDS,
        "notes": [
            "Original AgentRange source files are not modified.",
            "Compose !reset removes direct host port exposure from the original app/langflow services.",
            "Sidecars call /api/v1/inspect/* on the DefenseClaw gateway and fail open by default.",
            "Sidecars emit agentrange-runtime-* audit events with the unified event model for chain reconstruction.",
        ],
    }
    if discovery.langflow_service:
        plan["routes"].append(
            {
                "kind": "langflow",
                "from": "host",
                "via": "defenseclaw-langflow-ingress",
                "to": discovery.langflow_service,
            }
        )
    return plan


def _compose_override(plan: dict[str, Any]) -> dict[str, Any]:
    discovery = plan["services"]
    rewrites = plan["rewrites"]
    networks = _network_list_from_plan(plan)
    source_compose_dir = Path(plan["source"]["compose_path"]).resolve().parent
    sidecar_source = Path(plan["source"]["sidecar_source"])
    sidecar_mount = f"{_docker_host_path(sidecar_source, base_dir=source_compose_dir)}"
    sidecar_mount += ":/opt/defenseclaw/agentrange_sidecar.py:ro"
    token_env_file = _portable_path(Path.cwd() / ".defenseclaw-home" / ".env", base_dir=source_compose_dir)
    common_env = {
        "PYTHONUNBUFFERED": "1",
        "DC_GATEWAY_BASE": plan["gateway"]["base_url"],
        "DC_FAIL_MODE": plan["gateway"]["fail_mode"],
        "DC_INSPECT_TIMEOUT_MS": str(plan["gateway"]["inspect_timeout_ms"]),
        "DC_CONNECTOR": "agentrange",
    }
    common_service = {
        "image": "python:3.12-slim",
        "command": "python /opt/defenseclaw/agentrange_sidecar.py",
        "env_file": [token_env_file],
        "volumes": [sidecar_mount],
        "extra_hosts": ["host.docker.internal:host-gateway"],
        "networks": networks,
    }

    services: dict[str, Any] = {
        discovery["opspilot"]: {
            "environment": rewrites["opspilot_environment"],
            "ports": ComposeResetList(),
        },
        "defenseclaw-opspilot-ingress": {
            **common_service,
            "environment": {
                **common_env,
                "DC_PROXY_KIND": "opspilot",
                "DC_TARGET_BASE": f"http://{discovery['opspilot']}:8000",
                "DC_LISTEN_PORT": "8000",
            },
            "depends_on": [discovery["opspilot"]],
            "ports": [_port_value(port) for port in plan["ingress"]["opspilot"]["ports"]],
        },
    }

    if discovery.get("llm_target_base"):
        services["defenseclaw-llm-proxy"] = {
            **common_service,
            "environment": {
                **common_env,
                "DC_PROXY_KIND": "llm",
                "DC_TARGET_BASE": discovery["llm_target_base"],
                "DC_LISTEN_PORT": "8000",
            },
            "depends_on": [_target_host(discovery["llm_target_base"])],
        }

    if discovery.get("mcp_targets"):
        services["defenseclaw-mcp-proxy"] = {
            **common_service,
            "environment": {
                **common_env,
                "DC_PROXY_KIND": "mcp",
                "DC_MCP_TARGETS": json.dumps(discovery["mcp_targets"], sort_keys=True),
                "DC_LISTEN_PORT": "8000",
            },
            "depends_on": sorted(discovery["mcp_targets"].keys()),
        }

    if discovery.get("langflow"):
        services[discovery["langflow"]] = {
            "environment": rewrites.get("langflow_environment", {}),
            "ports": ComposeResetList(),
        }
        services["defenseclaw-langflow-ingress"] = {
            **common_service,
            "environment": {
                **common_env,
                "DC_PROXY_KIND": "langflow",
                "DC_TARGET_BASE": "http://langflow:7860",
                "DC_LISTEN_PORT": "7860",
            },
            "depends_on": [discovery["langflow"]],
            "ports": [_port_value(port) for port in plan["ingress"]["langflow"]["ports"]],
        }

    return {
        "services": services,
        "x-defenseclaw-agentrange": {
            "non_invasive": True,
            "source_compose": plan["source"].get("portable_compose_path", plan["source"]["compose_path"]),
            "gateway_base": plan["gateway"]["base_url"],
            "routes": plan["routes"],
            "event_model": plan["event_model"],
        },
    }


def _network_list_from_plan(plan: dict[str, Any]) -> list[str]:
    discovery = discover_agentrange(plan["source"]["range_root"])
    return discovery.networks


def _target_host(url: str) -> str:
    parsed = urlsplit(url)
    return parsed.hostname or url


def _port_value(port: dict[str, Any]) -> str:
    return PortBinding(
        published=str(port["published"]),
        target=str(port["target"]),
        protocol=str(port.get("protocol") or "tcp"),
        host_ip=str(port.get("host_ip") or ""),
    ).compose_value()


def _docker_host_path(path: Path, *, base_dir: Path | None = None) -> str:
    resolved = path.resolve()
    if base_dir is not None:
        try:
            return Path(os.path.relpath(resolved, start=base_dir.resolve())).as_posix()
        except ValueError:
            pass
    return resolved.as_posix()


def _dump_compose(data: dict[str, Any]) -> str:
    return yaml.dump(data, Dumper=ComposeDumper, sort_keys=False, allow_unicode=True, default_flow_style=False)


def _portable_path(path: Path, *, base_dir: Path) -> str:
    try:
        return Path(os.path.relpath(path.resolve(), start=base_dir.resolve())).as_posix()
    except ValueError:
        # A generated bundle may live on another Windows drive than the
        # checkout. Keep repository-owned sources portable in the public plan;
        # the compose renderer still uses the original absolute path.
        repo_root = Path(__file__).resolve().parents[2]
        try:
            return path.resolve().relative_to(repo_root).as_posix()
        except ValueError:
            return str(path.resolve())


def _public_plan(plan: dict[str, Any]) -> dict[str, Any]:
    public = json.loads(json.dumps(plan, ensure_ascii=False))
    source = public.get("source", {})
    source["range_root"] = source.pop("portable_range_root", source.get("range_root", ""))
    source["compose_path"] = source.pop("portable_compose_path", source.get("compose_path", ""))
    source["sidecar_source"] = source.pop("portable_sidecar_source", source.get("sidecar_source", ""))
    return public


def _render_readme(plan: dict[str, Any], output_dir: Path) -> str:
    override = "docker-compose.defenseclaw.override.yml"
    compose_path = Path(plan["source"]["compose_path"])
    source = (
        _portable_path(compose_path, base_dir=output_dir)
        if compose_path.is_absolute()
        else compose_path.as_posix()
    )
    gateway = plan["gateway"]["base_url"]
    return f"""# AgentRange Non-Invasive DefenseClaw Adapter

This bundle was generated from:

```text
{source}
```

It keeps the original AgentRange source tree unchanged. Runtime traffic is
routed through DefenseClaw-owned sidecars:

- host -> `defenseclaw-opspilot-ingress` -> OpsPilot `/run`
- OpsPilot -> `defenseclaw-llm-proxy` -> original LLM stub
- OpsPilot -> `defenseclaw-mcp-proxy` -> original MCP servers
- host -> `defenseclaw-langflow-ingress` -> original Langflow service

Before starting the range, make sure the DefenseClaw sidecar API is reachable
from Docker containers at:

```text
{gateway}
```

If your gateway requires a token, sidecars load it from:

```text
../../.defenseclaw-home/.env
```

This file is generated by `defenseclaw init` and ignored by Git.

Start AgentRange with the generated overlay:

```powershell
docker compose -f "{source}" -f "{override}" up --build
```

The overlay uses Docker Compose `!reset []` to remove direct host port exposure
from the original OpsPilot and Langflow services, then republishes those ports
on DefenseClaw ingress sidecars.
"""


def _is_relative_to(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False
