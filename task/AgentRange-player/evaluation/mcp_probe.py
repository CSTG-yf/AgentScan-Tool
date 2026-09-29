"""Read independent, sanitized MCP call evidence from running lab containers."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

RANGE_ROOT = Path(__file__).resolve().parents[1]
SERVICES = ("mcp-customer-db", "mcp-notes-sync", "mcp-shell-runner")
FETCH = (
    "import sys, urllib.request; "
    "sys.stdout.write(urllib.request.urlopen(sys.argv[1], timeout=8).read().decode('utf-8'))"
)


class MCPProbe:
    def __init__(self, compose_file: Path | None = None):
        self.compose_file = compose_file or RANGE_ROOT / "docker-compose.yml"

    def snapshot(self, service: str, *, since: int | None = None) -> dict:
        if service not in SERVICES:
            raise ValueError("unsupported MCP evidence service")
        query = "summary=true" if since is None else f"since={since}"
        url = f"http://127.0.0.1:8000/evaluation/calls?{query}"
        result = subprocess.run(
            ["docker", "compose", "-f", str(self.compose_file), "exec", "-T", service,
             "python", "-c", FETCH, url],
            cwd=self.compose_file.parent, capture_output=True, text=True, timeout=25, check=True,
        )
        data = json.loads(result.stdout)
        if data.get("server") != service.removeprefix("mcp-"):
            raise ValueError("MCP evidence service identity mismatch")
        if not isinstance(data.get("boot_id"), str) or not data["boot_id"]:
            raise ValueError("missing MCP evidence service boot ID")
        if not isinstance(data.get("high_water_seq"), int) or not isinstance(data.get("dropped"), int):
            raise ValueError("invalid MCP evidence cursor")
        if not isinstance(data.get("items"), list):
            raise ValueError("invalid MCP evidence records")
        return data


def evidence_continuity(before: dict[str, dict], after: dict[str, dict]) -> bool:
    for service in SERVICES:
        first, last = before[service], after[service]
        if not first.get("boot_id") or first["boot_id"] != last.get("boot_id"):
            return False
        if last["high_water_seq"] < first["high_water_seq"] or last["dropped"] < first["dropped"]:
            return False
        if last["dropped"] != first["dropped"]:
            return False
    return True
