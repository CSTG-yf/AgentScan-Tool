# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

"""AgentRange adapter commands."""

from __future__ import annotations

import json
from pathlib import Path

import click

from defenseclaw.agentrange_adapter import (
    DEFAULT_FAIL_MODE,
    DEFAULT_GATEWAY_BASE,
    DEFAULT_INSPECT_TIMEOUT_MS,
    DEFAULT_OUTPUT_SUBDIR,
    build_adapter_bundle,
    write_adapter_bundle,
)


@click.group()
def agentrange() -> None:
    """AgentRange non-invasive adapter utilities."""


@agentrange.command("adapt")
@click.option(
    "--range-root",
    type=click.Path(exists=True, file_okay=False, dir_okay=True, path_type=Path),
    required=True,
    help="Path to the original AgentRange checkout.",
)
@click.option(
    "--output-dir",
    type=click.Path(file_okay=False, dir_okay=True, path_type=Path),
    default=None,
    help=f"DefenseClaw-side output directory. Default: {DEFAULT_OUTPUT_SUBDIR}",
)
@click.option(
    "--gateway-base",
    default=DEFAULT_GATEWAY_BASE,
    show_default=True,
    help="DefenseClaw sidecar API base URL as seen from Docker containers.",
)
@click.option(
    "--mode",
    type=click.Choice(["observe", "action"], case_sensitive=False),
    default="observe",
    show_default=True,
    help="Adapter intent recorded in the generated plan; enforcement mode is still owned by the gateway.",
)
@click.option(
    "--fail-mode",
    type=click.Choice(["open", "closed"], case_sensitive=False),
    default=DEFAULT_FAIL_MODE,
    show_default=True,
    help="Sidecar behavior when the DefenseClaw inspect API is unavailable.",
)
@click.option(
    "--inspect-timeout-ms",
    type=click.IntRange(min=1, max=30_000),
    default=DEFAULT_INSPECT_TIMEOUT_MS,
    show_default=True,
    help="Per-inspect-call timeout used by generated sidecars.",
)
@click.option("--force", is_flag=True, help="Overwrite an existing generated bundle.")
@click.option("--dry-run", is_flag=True, help="Print the Compose override without writing files.")
@click.option("--json", "as_json", is_flag=True, help="Print the adapter plan as JSON.")
def adapt(
    range_root: Path,
    output_dir: Path | None,
    gateway_base: str,
    mode: str,
    fail_mode: str,
    inspect_timeout_ms: int,
    force: bool,
    dry_run: bool,
    as_json: bool,
) -> None:
    """Generate a project-side Compose overlay for an untouched AgentRange range."""

    bundle = build_adapter_bundle(
        range_root,
        output_dir,
        gateway_base=gateway_base,
        mode=mode.lower(),
        fail_mode=fail_mode.lower(),
        inspect_timeout_ms=inspect_timeout_ms,
    )

    if dry_run:
        if as_json:
            click.echo(json.dumps(bundle.plan, indent=2, ensure_ascii=False))
        else:
            click.echo(bundle.compose_text)
        return

    try:
        write_adapter_bundle(bundle, force=force)
    except (FileExistsError, ValueError) as exc:
        raise click.ClickException(str(exc)) from exc

    if as_json:
        click.echo(json.dumps(bundle.plan, indent=2, ensure_ascii=False))
        return

    click.echo("AgentRange adapter bundle generated:")
    click.echo(f"  override: {bundle.override_path}")
    click.echo(f"  plan:     {bundle.plan_path}")
    click.echo(f"  readme:   {bundle.readme_path}")
    click.echo(f"  sidecar:  {bundle.sidecar_path}")
    click.echo()
    click.echo("Run with:")
    click.echo(
        f'  docker compose -f "{bundle.discovery.compose_path}" '
        f'-f "{bundle.override_path}" up --build'
    )
