"""Standalone sandbox command bundled with the desktop installers.

This entry point intentionally imports only ai_sandbox and the Python standard
library, so the desktop installer does not need a system Python installation.
"""

from __future__ import annotations

import argparse
import os
import shlex
import subprocess
import sys

from ai_sandbox.approval import ApprovalGate
from ai_sandbox.registry import get_report, get_sandbox_backend


def _ask(source: str, tool: str, reasons: list[str]) -> str:
    print(f"Approval required for {tool}: {source}", file=sys.stderr)
    for reason in reasons:
        print(f"  {reason}", file=sys.stderr)
    if not sys.stdin.isatty():
        return "denied"
    answer = input("Run this command once? [y/N] ").strip().lower()
    return "approved" if answer in {"y", "yes"} else "denied"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="TraceBastion managed local sandbox")
    subcommands = parser.add_subparsers(dest="action", required=True)
    subcommands.add_parser("status", help="Probe the local OS sandbox backend")
    execute = subcommands.add_parser("exec", help="Execute one command in the sandbox")
    execute.add_argument("--workspace", required=True)
    execute.add_argument("--timeout", type=int, default=120)
    execute.add_argument("--mode", choices=("manual", "auto"), default="manual")
    execute.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)

    report = get_report()
    if args.action == "status":
        print(f"Backend: {report.name or 'unavailable'}")
        print(f"Isolation: {report.level}")
        for failure in report.failures:
            print(f"Unavailable {failure.backend} ({failure.form}): {failure.message}")
    if report.degraded or report.name is None or report.level == "none":
        print("No OS sandbox is available; execution is disabled", file=sys.stderr)
        return 2
    if args.action == "status":
        return 0

    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    if not command:
        parser.error("Provide a command after --")
    if not 1 <= args.timeout <= 3600:
        parser.error("--timeout must be between 1 and 3600 seconds")
    workspace = os.path.realpath(args.workspace)
    if not os.path.isdir(workspace):
        parser.error("--workspace must be an existing directory")
    if os.name == "nt" and os.path.lexists(os.path.join(workspace, ".git")):
        print("AppContainer cannot safely use an existing .git workspace", file=sys.stderr)
        return 2

    source = subprocess.list2cmdline(command) if os.name == "nt" else shlex.join(command)
    rejected = ApprovalGate(ask_handler=_ask, default_mode=args.mode).check(source, tool="shell")
    if rejected:
        print(rejected, file=sys.stderr)
        return 2

    runner = None
    try:
        runner = get_sandbox_backend().make_runner(workspace)
        result = runner.run(command, runner.agent_root(), timeout=args.timeout)
    except subprocess.TimeoutExpired:
        print(f"Sandbox command timed out after {args.timeout}s", file=sys.stderr)
        return 124
    except (OSError, ValueError, RuntimeError) as error:
        print(f"Sandbox command failed: {error}", file=sys.stderr)
        return 2
    finally:
        if runner is not None:
            close = getattr(runner, "close", None)
            if close is not None:
                close()
    if result.stdout:
        print(result.stdout, end="")
    if result.stderr:
        print(result.stderr, end="", file=sys.stderr)
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
