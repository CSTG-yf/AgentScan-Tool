import pathlib
import re

import yaml


def load_skill(skill_dir: str) -> dict:
    text = (pathlib.Path(skill_dir) / "SKILL.md").read_text(encoding="utf-8")
    # frontmatter 解析只覆盖靶场需要的字段，保持加载逻辑可读。
    match = re.match(r"^---\n(.*?)\n---\n(.*)$", text, re.DOTALL)
    if not match:
        return {"name": pathlib.Path(skill_dir).name, "body": text, "allowed_tools": []}
    meta = yaml.safe_load(match.group(1)) or {}
    return {
        "name": meta.get("name", pathlib.Path(skill_dir).name),
        "description": meta.get("description", ""),
        "allowed_tools": meta.get("allowed-tools", []),
        "body": match.group(2),
    }
