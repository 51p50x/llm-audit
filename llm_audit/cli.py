"""llm-audit CLI entry point — powered by Typer."""

from __future__ import annotations

import asyncio
import pathlib
import sys
from typing import Annotated, Optional

import typer
from rich.console import Console

from llm_audit import __version__
from llm_audit.exceptions import LLMAuditError
from llm_audit.probes import ALL_PROBES
from llm_audit.reporter import render_error, render_json, render_report
from llm_audit.runner import run_audit
from llm_audit.types import AuditConfig, PROBE_GROUPS

app = typer.Typer(
    name="llm-audit",
    help="Audit LLM endpoints against OWASP LLM Top 10.",
    add_completion=False,
    rich_markup_mode="rich",
)

console = Console()

_PROBE_NAMES = ", ".join(ALL_PROBES.keys())
_GROUP_NAMES = ", ".join(k for k in PROBE_GROUPS if k != "all")


def _version_callback(value: bool) -> None:
    if value:
        console.print(f"[bold cyan]llm-audit[/bold cyan] v{__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: Annotated[
        Optional[bool],
        typer.Option(
            "--version", "-V",
            help="Show version and exit.",
            callback=_version_callback,
            is_eager=True,
        ),
    ] = None,
) -> None:
    """llm-audit — OWASP LLM Top 10 security auditing tool."""


@app.command()
def audit(
    endpoint: Annotated[
        str,
        typer.Argument(help="OpenAI-compatible chat completions endpoint URL."),
    ],
    api_key: Annotated[
        Optional[str],
        typer.Option(
            "--api-key", "-k",
            envvar="LLM_AUDIT_API_KEY",
            help="Bearer token for the endpoint. Prefer the LLM_AUDIT_API_KEY env var.",
            show_default=False,
        ),
    ] = None,
    model: Annotated[
        Optional[str],
        typer.Option(
            "--model", "-m",
            help="Model name to pass in the request payload (e.g. gpt-4o).",
        ),
    ] = None,
    system_prompt: Annotated[
        Optional[str],
        typer.Option(
            "--system-prompt", "-s",
            help="System prompt to include in every probe request.",
        ),
    ] = None,
    timeout: Annotated[
        float,
        typer.Option(
            "--timeout", "-t",
            help="HTTP request timeout in seconds. Default 120s — increase for slow local models.",
            min=1.0,
            max=600.0,
        ),
    ] = 120.0,
    auth: Annotated[
        Optional[str],
        typer.Option(
            "--auth",
            envvar="LLM_AUDIT_AUTH",
            help=(
                "Full Authorization header value (e.g. 'Bearer sk-xxx', 'ApiKey abc'). "
                "Takes precedence over --api-key."
            ),
            show_default=False,
        ),
    ] = None,
    probes: Annotated[
        Optional[str],
        typer.Option(
            "--probes", "-p",
            help=(
                f"Comma-separated list of probes to run. "
                f"Available: {_PROBE_NAMES}. "
                "Omit to run all probes."
            ),
        ),
    ] = None,
    only: Annotated[
        Optional[str],
        typer.Option(
            "--only",
            help=(
                f"Shorthand group filter. "
                f"Available groups: {_GROUP_NAMES}. "
                "Expands to the probes in that group. Overrides --probes."
            ),
        ),
    ] = None,
    output_file: Annotated[
        Optional[str],
        typer.Option(
            "--output", "-o",
            help="Save the report to a file (JSON or Rich text depending on --format).",
            show_default=False,
        ),
    ] = None,
    concurrency: Annotated[
        int,
        typer.Option(
            "--concurrency", "-c",
            help="Max number of probes running in parallel. Use 1 for slow local models.",
            min=1,
            max=10,
        ),
    ] = 2,
    output_format: Annotated[
        str,
        typer.Option(
            "--format", "-f",
            help="Output format: 'rich' (default) or 'json'.",
        ),
    ] = "rich",
    verbose: Annotated[
        bool,
        typer.Option(
            "--verbose", "-v",
            help="Show evidence and recommendations even for passing probes.",
        ),
    ] = False,
) -> None:
    """Run a security audit against an LLM [bold cyan]ENDPOINT[/bold cyan].

    \b
    Examples:
      llm-audit audit https://api.openai.com/v1/chat/completions --api-key $OPENAI_KEY --model gpt-4o
      llm-audit audit http://localhost:11434/v1/chat/completions --model llama3
      llm-audit audit https://my-llm.example.com/chat --probes prompt_injection,jailbreak
    """
    if output_format not in ("rich", "json"):
        render_error(f"Invalid format '{output_format}'. Choose 'rich' or 'json'.")
        raise typer.Exit(code=1)

    if only is not None:
        if only not in PROBE_GROUPS:
            render_error(
                f"Unknown group '{only}'. Available groups: {_GROUP_NAMES}."
            )
            raise typer.Exit(code=1)
        probe_list = PROBE_GROUPS[only]
    elif probes:
        probe_list = [p.strip() for p in probes.split(",") if p.strip()]
    else:
        probe_list = []

    config = AuditConfig(
        endpoint=endpoint,
        api_key=api_key,
        auth_header=auth,
        model=model,
        system_prompt=system_prompt,
        timeout=timeout,
        probes=probe_list,
        output_format=output_format,  # type: ignore[arg-type]
        output_file=output_file,
        concurrency=concurrency,
        verbose=verbose,
    )

    try:
        report = asyncio.run(run_audit(config))
    except LLMAuditError as exc:
        render_error(str(exc))
        raise typer.Exit(code=2) from exc
    except KeyboardInterrupt:
        console.print("\n[yellow]Audit interrupted by user.[/yellow]")
        raise typer.Exit(code=130)

    if output_file:
        path = pathlib.Path(output_file)
        with path.open("w", encoding="utf-8") as fh:
            if output_format == "json":
                render_json(report, output=fh)
            else:
                render_report(report, verbose=verbose, output=fh)
        console.print(f"[dim]Report saved to[/dim] [bold cyan]{path.resolve()}[/bold cyan]")
    elif output_format == "json":
        render_json(report)
    else:
        render_report(report, verbose=verbose)

    failed = report["summary"]["failed"]
    raise typer.Exit(code=1 if failed > 0 else 0)


@app.command()
def list_probes() -> None:
    """List all available probes with their OWASP IDs and descriptions."""
    from rich.table import Table
    from rich import box
    from llm_audit.probes.base import BaseProbe

    table = Table(
        title="[bold cyan]Available Probes[/bold cyan]",
        box=box.ROUNDED,
        show_header=True,
        header_style="bold white",
    )
    table.add_column("Name", style="bold cyan")
    table.add_column("OWASP ID", style="yellow")
    table.add_column("Description")

    for probe_key, probe_cls in ALL_PROBES.items():
        instance: BaseProbe = probe_cls.__new__(probe_cls)
        table.add_row(probe_key, probe_cls.owasp_id, probe_cls.description)

    console.print(table)
