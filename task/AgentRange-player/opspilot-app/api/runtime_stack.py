"""Capture a bounded, privacy-safe Python application call stack."""

from __future__ import annotations

import traceback
from pathlib import Path
from typing import Iterable

MAX_STACK_FRAMES = 16
_APP_MODULES = {"api", "policy", "skills"}


def runtime_stack_frames(
    *,
    app_root: Path | None = None,
    frames: Iterable[traceback.FrameSummary] | None = None,
) -> list[dict[str, str | int]]:
    """Return real app frames as relative file/function/line evidence.

    Function arguments, source lines, and absolute machine/container paths are
    intentionally excluded. Keeping only application modules makes the
    evidence useful without disclosing request data or deployment details.
    """
    root = (app_root or Path(__file__).resolve().parents[1]).resolve()
    stack = list(frames if frames is not None else traceback.extract_stack(limit=64)[:-1])
    captured: list[dict[str, str | int]] = []
    for frame in stack:
        source = Path(frame.filename).resolve()
        try:
            relative = source.relative_to(root)
        except ValueError:
            continue
        if not relative.parts or relative.parts[0] not in _APP_MODULES:
            continue
        if relative.as_posix() == "api/runtime_stack.py":
            continue
        if not frame.name or frame.lineno <= 0:
            continue
        captured.append({
            "file": relative.as_posix(),
            "function": frame.name[:128],
            "line": int(frame.lineno),
        })
    return captured[-MAX_STACK_FRAMES:]
