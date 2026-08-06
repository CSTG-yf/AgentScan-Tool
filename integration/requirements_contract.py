"""Evaluate implementation and evidence readiness for the DefenseClaw plan."""

from __future__ import annotations

from pathlib import Path

import yaml


def load(path: Path | None = None) -> dict:
    target = path or Path(__file__).with_name("requirements.yaml")
    return yaml.safe_load(target.read_text(encoding="utf-8"))


def evaluate(repo_root: Path, path: Path | None = None) -> dict:
    contract = load(path)
    rows = []
    seen = set()
    for requirement in contract.get("requirements", []):
        requirement_id = str(requirement.get("id") or "")
        if not requirement_id or requirement_id in seen:
            raise ValueError(f"duplicate or empty requirement id: {requirement_id!r}")
        seen.add(requirement_id)
        implementation = [str(item) for item in requirement.get("implementation", [])]
        verification = [str(item) for item in requirement.get("verification", [])]
        if not implementation or not verification:
            raise ValueError(f"{requirement_id} must map implementation and verification artifacts")
        missing_implementation = [item for item in implementation if not (repo_root / item).exists()]
        missing_verification = [item for item in verification if not (repo_root / item).exists()]
        if missing_implementation:
            status = "not-implemented"
        elif missing_verification:
            status = "implemented-awaiting-evidence"
        else:
            status = "evidence-ready"
        rows.append(
            {
                "id": requirement_id,
                "task": requirement["task"],
                "title": requirement["title"],
                "status": status,
                "missing_implementation": missing_implementation,
                "missing_verification": missing_verification,
            }
        )
    return {
        "plan": contract.get("plan"),
        "requirements": rows,
        "counts": {
            status: sum(row["status"] == status for row in rows)
            for status in ("not-implemented", "implemented-awaiting-evidence", "evidence-ready")
        },
    }
