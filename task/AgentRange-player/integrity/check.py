"""Verify the seven fixture skills before building or replaying AgentRange."""

from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import shutil
import sys
import tempfile


ROOT = Path(__file__).resolve().parent.parent
EXPECTED = {
    "skills/code-review/SKILL.md": "e04e62694d181cd199c89309768f4d3d04e3e4a6736b2cbfc175dd756d786ae2",
    "skills/incident-runbook/SKILL.md": "ce33affff2a7ecec2709a15195d928ef452f5859882fe67ab13d16e06a90267e",
    "skills/meeting-summary/SKILL.md": "983fa680d832ff9b1eff4b3c89229ebb13fa1aa1662779528b238ff5b4c52baf",
    "skills/password-policy-check/SKILL.md": "1e6969b432ce7ff3262449636401c1554b4bb9cd05f6e59df2bb6308b4d0cdf9",
    "skills/pdf-export/SKILL.md": "d56ceedab0a8493887d5b25b12a481e942d73e76e90d79f4057630044d918d13",
    "skills/pii-redaction/SKILL.md": "ea080893e1db284edc53c6c3f8c590b5c73c7a062fecc195f48846f569fd9fe4",
    "skills/sql-report/SKILL.md": "e8b50d6eca05a93e4b46b4b6191dd9ca5046b10b70c4a5360424518d4c7e40ce",
}


def digest(path: Path) -> str:
    data = path.read_bytes().replace(b"\r\n", b"\n").rstrip(b"\n") + b"\n"
    return hashlib.sha256(data).hexdigest()


def check(root: Path, repair: bool, quarantine_root: Path | None) -> list[str]:
    baseline_root = root / "integrity" / "baseline"
    missing: list[str] = []
    for relative, expected in EXPECTED.items():
        baseline = baseline_root / relative
        if not baseline.is_file() or digest(baseline) != expected:
            raise ValueError(f"trusted baseline missing or changed: {baseline}")
        target = root / relative
        if any(parent.is_symlink() for parent in (target, target.parent, target.parent.parent)):
            raise ValueError(f"refusing symlink target: {target}")
        if target.is_file():
            if digest(target) != expected:
                raise ValueError(f"fixture content differs from baseline: {target}")
        elif target.exists():
            raise ValueError(f"fixture is not a regular file: {target}")
        else:
            missing.append(relative)

    if missing and not repair:
        raise ValueError(
            "missing fixture skills: " + ", ".join(missing) + "; run integrity/check.py --repair"
        )

    for relative in missing:
        target = root / relative
        source = baseline_root / relative
        if quarantine_root is not None:
            quarantined = quarantine_root / Path(relative).parent.name / "SKILL.md"
            if quarantined.is_file() and digest(quarantined) == EXPECTED[relative]:
                source = quarantined
        target.parent.mkdir(parents=True, exist_ok=True)
        fd, temporary = tempfile.mkstemp(prefix=".restore-", dir=target.parent)
        try:
            with os.fdopen(fd, "wb") as output, source.open("rb") as input_file:
                shutil.copyfileobj(input_file, output)
            os.replace(temporary, target)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)
        if digest(target) != EXPECTED[relative]:
            raise ValueError(f"fixture restore failed verification: {target}")
        print(f"restored {relative} from {source}")
    return missing


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repair", action="store_true", help="restore missing fixtures")
    parser.add_argument("--root", type=Path, default=ROOT, help="AgentRange root (defaults to script parent)")
    parser.add_argument("--quarantine-root", type=Path, help="optional trusted quarantine/skills directory")
    args = parser.parse_args()
    try:
        check(args.root, args.repair, args.quarantine_root)
    except (OSError, ValueError) as error:
        print(f"AgentRange integrity check failed: {error}", file=sys.stderr)
        return 1
    print("AgentRange fixture skills verified (7/7)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
