"""OpenShell lifecycle and local, managed command execution."""

from __future__ import annotations

import os
import shlex
import subprocess

import click

from defenseclaw.commands.cmd_init_sandbox import sandbox_init_cmd
from defenseclaw.commands.cmd_setup_sandbox import setup_sandbox
from defenseclaw.context import pass_ctx


@click.group()
def sandbox() -> None:
    """Manage OpenShell or execute a command in a local OS sandbox.

    \b
    init/setup retain the Linux OpenClaw lifecycle. status/exec use a
    platform backend for a single managed command. Requires init first.
    """


sandbox.add_command(sandbox_init_cmd, "init")
sandbox.add_command(setup_sandbox, "setup")


@sandbox.command("status")
def sandbox_status() -> None:
    """Show the actual local backend and its isolation level."""
    from ai_sandbox.registry import get_report

    report = get_report()
    click.echo(f"Backend: {report.name or 'unavailable'}")
    click.echo(f"Isolation: {report.level}")
    for failure in report.failures:
        click.echo(f"Unavailable {failure.backend} ({failure.form}): {failure.message}")
    if report.degraded or report.name is None:
        raise click.ClickException("No OS sandbox is available; managed execution is disabled")


def _approval_prompt(source: str, tool: str, reasons: list[str]) -> str:
    click.echo(f"Approval required for {tool}: {source}", err=True)
    for reason in reasons:
        click.echo(f"  {reason}", err=True)
    if not click.get_text_stream("stdin").isatty():
        return "denied"
    return "approved" if click.confirm("Run this command once?", default=False) else "denied"


@sandbox.command("exec", context_settings={"ignore_unknown_options": True})
@click.option("--workspace", required=True, type=click.Path(exists=True, file_okay=False, resolve_path=True))
@click.option("--timeout", type=click.IntRange(min=1, max=3600), default=120, show_default=True)
@click.option("--mode", type=click.Choice(["manual", "auto"]), default="manual", show_default=True)
@click.argument("command", nargs=-1, type=click.UNPROCESSED)
@pass_ctx
def sandbox_exec(app, workspace: str, timeout: int, mode: str,
                 command: tuple[str, ...]) -> None:
    """Run a noninteractive command in the selected OS sandbox.

    The command and its children run inside the backend. This does not
    attach to agents that were started separately. Use -- before COMMAND.
    """
    from ai_sandbox.approval import ApprovalGate
    from ai_sandbox.registry import get_report, get_sandbox_backend

    if not command:
        raise click.UsageError("Provide a command after --")
    report = get_report()
    if report.degraded or report.name is None or report.level == "none":
        if app.logger:
            app.logger.log_action("managed-sandbox-denied", workspace, "reason=no-os-backend")
        raise click.ClickException("No OS sandbox is available; refusing direct execution")

    # Existing repositories cannot be safely remapped by the extracted
    # AppContainer runner without changing their host ACLs. Reject them.
    if os.name == "nt" and os.path.lexists(os.path.join(workspace, ".git")):
        raise click.ClickException("AppContainer cannot safely use an existing .git workspace")

    source = subprocess.list2cmdline(command) if os.name == "nt" else shlex.join(command)
    gate = ApprovalGate(ask_handler=_approval_prompt, default_mode=mode)
    rejected = gate.check(source, tool="shell")
    if rejected:
        if app.logger:
            app.logger.log_action("managed-sandbox-denied", workspace, "reason=approval")
        raise click.ClickException(rejected)

    backend = get_sandbox_backend()
    runner = None
    try:
        runner = backend.make_runner(workspace)
        if app.logger:
            app.logger.log_action("managed-sandbox-start", workspace,
                                  f"backend={report.name} isolation={report.level}")
        result = runner.run(list(command), runner.agent_root(), timeout=timeout)
    except subprocess.TimeoutExpired:
        if app.logger:
            app.logger.log_action("managed-sandbox-exit", workspace, "result=timeout")
        raise click.ClickException(f"Sandbox command timed out after {timeout}s")
    except (OSError, ValueError, RuntimeError) as exc:
        if app.logger:
            app.logger.log_action("managed-sandbox-exit", workspace, "result=error")
        raise click.ClickException(f"Sandbox command failed: {exc}") from exc
    finally:
        if runner is not None:
            close = getattr(runner, "close", None)
            if close is not None:
                close()

    if result.stdout:
        click.echo(result.stdout, nl=False)
    if result.stderr:
        click.echo(result.stderr, nl=False, err=True)
    if app.logger:
        app.logger.log_action("managed-sandbox-exit", workspace,
                              f"backend={report.name} exit_code={result.returncode}")
    if result.returncode:
        raise SystemExit(result.returncode)
