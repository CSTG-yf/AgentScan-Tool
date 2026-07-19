"""Deterministic AgentRange asset and configuration risk scanner."""

from __future__ import annotations

import argparse
import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

import yaml


TEXT_SUFFIXES = {".py", ".md", ".yaml", ".yml", ".env", ".example", ".json", ".toml"}
SCAN_ROOTS = ("skills", "mcp", "opspilot-app", "langflow", "docker-compose.yml", ".env.example")


def load_yaml(path: Path) -> dict:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def iter_sources(root: Path):
    for relative in SCAN_ROOTS:
        target = root / relative
        candidates = target.rglob("*") if target.is_dir() else [target]
        for path in candidates:
            if not path.is_file() or "__pycache__" in path.parts:
                continue
            if path.suffix.lower() in TEXT_SUFFIXES or path.name in {"Dockerfile", ".env.example", "SKILL.md"}:
                yield path


def asset_for_source(source: str, assets: list[dict]) -> str:
    normalized = source.replace("\\", "/")
    exact = {asset["source"].replace("\\", "/"): asset["id"] for asset in assets}
    if normalized in exact:
        return exact[normalized]
    for asset in assets:
        asset_source = asset["source"].replace("\\", "/")
        if "/" in asset_source and normalized.startswith(asset_source.rsplit("/", 1)[0] + "/"):
            return asset["id"]
    if normalized in {".env.example", "docker-compose.yml"}:
        return "agent.opspilot"
    return "unmapped." + normalized.replace("/", ".")


def scan(root: Path) -> dict:
    contract = load_yaml(root / "contracts" / "assets.yaml")
    taxonomy = load_yaml(root / "integration" / "risk_taxonomy.yaml")
    assets = contract["assets"]
    findings = []
    seen = set()
    for path in iter_sources(root):
        relative = path.relative_to(root).as_posix()
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        for rule in taxonomy["rules"]:
            for pattern in rule["patterns"]:
                for line_number, line in enumerate(lines, 1):
                    if pattern.casefold() not in line.casefold():
                        continue
                    asset_id = asset_for_source(relative, assets)
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

    existing_assets = [asset for asset in assets if (root / asset["source"]).exists()]
    required = {tuple(item) for item in taxonomy["acceptance"]["required_rule_assets"]}
    detected = {(item["rule_id"], item["asset_id"]) for item in findings}
    benign = set(taxonomy["acceptance"]["benign_controls"])
    high_risk_benign = [item for item in findings if item["asset_id"] in benign and item["severity"] in {"HIGH", "CRITICAL"}]
    return {
        "schema_version": 1,
        "generated_at": datetime.now(UTC).isoformat(),
        "assets": existing_assets,
        "asset_edges": contract["edges"],
        "findings": findings,
        "metrics": {
            "asset_expected": len(assets),
            "asset_found": len(existing_assets),
            "asset_coverage": round(len(existing_assets) / len(assets), 6) if assets else 1.0,
            "required_risks": len(required),
            "required_risks_detected": len(required & detected),
            "risk_recall": round(len(required & detected) / len(required), 6) if required else 1.0,
            "high_risk_benign_findings": len(high_risk_benign),
        },
        "missing_required_risks": sorted([list(item) for item in required - detected]),
        "benign_control_violations": high_risk_benign,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    report = scan(args.root.resolve())
    output = args.output or args.root / "integration" / "reports" / "static-scan.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({"output": str(output), **report["metrics"]}, ensure_ascii=False, indent=2))
    return 0 if not report["missing_required_risks"] and not report["benign_control_violations"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
