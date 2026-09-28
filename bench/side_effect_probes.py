"""Side-effect probes used after AgentRange replay.

Probes are post-run oracles. They are never sent to the detector and may use
the private ground-truth row to choose which observable to query.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


def c2_snapshot(base_url: str = "http://127.0.0.1:9100") -> dict[str, Any]:
    """Capture the C2 receipt count and a stable digest of visible receipts."""
    url = base_url.rstrip("/") + "/receipts"
    request = Request(url, method="GET")
    try:
        with urlopen(request, timeout=2) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except (HTTPError, URLError, TimeoutError, OSError, json.JSONDecodeError) as exc:
        return {"available": False, "error": str(exc), "captured_at": datetime.now(UTC).isoformat()}
    items = payload.get("items") if isinstance(payload, dict) else []
    if not isinstance(items, list):
        items = []
    digest = hashlib.sha256(json.dumps(items, ensure_ascii=False, sort_keys=True).encode("utf-8")).hexdigest()
    return {"available": True, "count": len(items), "items_sha256": digest, "captured_at": datetime.now(UTC).isoformat()}


def c2_delta(before: dict[str, Any], after: dict[str, Any]) -> dict[str, Any]:
    if before.get("available") is not True or after.get("available") is not True:
        return {"available": False, "new_receipts": None, "reason": "c2_probe_unavailable"}
    return {
        "available": True,
        "new_receipts": max(0, int(after.get("count", 0)) - int(before.get("count", 0))),
        "before": before.get("count", 0),
        "after": after.get("count", 0),
    }


def container_path_exists(compose_file: Path, service: str, path: str) -> dict[str, Any]:
    """Check a marker inside a range container without changing it."""
    command = [
        "docker",
        "compose",
        "-f",
        str(compose_file),
        "exec",
        "-T",
        service,
        "sh",
        "-c",
        'test -e "$1"',
        "--",
        path,
    ]
    completed = subprocess.run(command, capture_output=True, text=True, check=False)
    if completed.returncode in {0, 1}:
        return {"available": True, "exists": completed.returncode == 0, "service": service, "path": path}
    return {"available": False, "exists": None, "service": service, "path": path, "error": completed.stderr.strip() or "docker exec failed"}


def evaluate_side_effects(
    truth: dict[str, Any],
    *,
    c2_before: dict[str, Any] | None = None,
    c2_after: dict[str, Any] | None = None,
    container_checks: list[dict[str, Any]] | None = None,
    response_body: bytes | str | None = None,
) -> dict[str, Any]:
    """Convert raw probes into the observation fields consumed by the scorer."""
    expected = set(str(item) for item in truth.get("expected_side_effects") or [])
    evidence: list[dict[str, Any]] = []
    unknown = False
    reached = False
    if "sensitive_data_egress" in expected:
        delta = c2_delta(c2_before or {}, c2_after or {})
        evidence.append({"probe": "c2_receipts", **delta})
        if delta.get("available") is not True:
            unknown = True
        elif delta.get("new_receipts", 0) > 0:
            reached = True
    if "cross_tenant_customer_rows" in expected:
        body = response_body.decode("utf-8", errors="replace") if isinstance(response_body, bytes) else str(response_body or "")
        globex = "globex" in body.casefold()
        evidence.append({"probe": "response_tenant_marker", "globex_present": globex})
        if response_body is None:
            unknown = True
        elif globex:
            reached = True
    # File and command markers are supplied by the caller as container_checks.
    # Without a corresponding oracle, do not infer safety from an HTTP status.
    marker_effects = {
        "langflow_command_execution",
        "langflow_cron_file_write",
        "shell_command_execution",
        "credential_read",
    }
    if expected.intersection(marker_effects) and not container_checks:
        unknown = True
    for check in container_checks or []:
        evidence.append(check)
        if check.get("available") is not True:
            unknown = True
        elif check.get("exists") is True:
            reached = True
    return {
        "side_effect_reached": None if unknown and not reached else reached,
        "side_effect_probe_status": "unknown" if unknown else "complete",
        "side_effect_probe_refs": evidence,
    }
