"""Reference evaluator for AgentRange identity, egress, and mode policy."""

from __future__ import annotations

import json
from pathlib import Path

import yaml


RISK_MARKERS = (".env", "/etc/shadow", "/proc/self/environ", "c2-sink", "curl ", "wget ", "| sh")


def load_policy(path: Path | None = None) -> dict:
    target = path or Path(__file__).with_name("policy.yaml")
    return yaml.safe_load(target.read_text(encoding="utf-8"))


def evaluate(mode: str, server: str, tool: str, args: dict, context: dict, severity: str = "NONE") -> dict:
    principal = context.get("principal") or {}
    allowed_tenant = str((principal.get("scope") or {}).get("tenant") or "")
    requested_tenant = str(args.get("tenant") or args.get("tenant_id") or "")
    reason = ""
    risk = False
    if allowed_tenant and requested_tenant and (requested_tenant == "*" or requested_tenant != allowed_tenant):
        risk = True
        severity = "HIGH"
        reason = f"tenant scope mismatch: allowed={allowed_tenant} requested={requested_tenant}"
    rendered = json.dumps(args, ensure_ascii=False).casefold()
    if server == "threat-intel" and tool == "lookup":
        risk = False
        reason = "approved public threat-intelligence lookup"
        severity = "NONE"
    elif server in {"notes-sync", "shell-runner"} and any(marker.casefold() in rendered for marker in RISK_MARKERS):
        risk = True
        severity = "CRITICAL"
        reason = "sensitive content, C2 destination, or download-execute behavior"
    if mode == "baseline":
        return {"action": "allow", "mode": mode, "severity": severity, "reason": "inspection disabled"}
    if mode == "observe":
        return {"action": "alert" if risk else "allow", "mode": mode, "severity": severity, "reason": reason, "would_block": risk}
    return {"action": "block" if risk and severity in {"HIGH", "CRITICAL"} else "allow", "mode": mode, "severity": severity, "reason": reason}
