"""llm-audit CLI entry point — powered by Typer."""

from __future__ import annotations

import asyncio
import pathlib
from typing import Annotated

import typer
from rich.console import Console

from llm_audit import __version__
from llm_audit.exceptions import LLMAuditError
from llm_audit.html_reporter import render_html
from llm_audit.probes import ALL_PROBES
from llm_audit.reporter import render_error, render_json, render_report
from llm_audit.runner import run_audit
from llm_audit.types import PROBE_GROUPS, AuditConfig

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
        bool | None,
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
        str | None,
        typer.Option(
            "--api-key", "-k",
            envvar="LLM_AUDIT_API_KEY",
            help="Bearer token for the endpoint. Prefer the LLM_AUDIT_API_KEY env var.",
            show_default=False,
        ),
    ] = None,
    model: Annotated[
        str | None,
        typer.Option(
            "--model", "-m",
            help="Model name to pass in the request payload (e.g. gpt-4o).",
        ),
    ] = None,
    system_prompt: Annotated[
        str | None,
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
        str | None,
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
        str | None,
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
        str | None,
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
        str | None,
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
    request_template: Annotated[
        str | None,
        typer.Option(
            "--request-template",
            help=(
                "Custom JSON request template. "
                "Use {message}, {system_prompt}, {model} as placeholders. "
                "Example: '{\"query\": \"{message}\", \"context\": \"{system_prompt}\"}'"
            ),
            show_default=False,
        ),
    ] = None,
    response_path: Annotated[
        str | None,
        typer.Option(
            "--response-path",
            help=(
                "Dot-notation path to extract text from the response JSON. "
                "Example: 'data.reply.text' or 'result.0.output'. "
                "Default: OpenAI format (choices.0.message.content)."
            ),
            show_default=False,
        ),
    ] = None,
    output_format: Annotated[
        str,
        typer.Option(
            "--format", "-f",
            help="Output format: 'rich' (default), 'json', or 'html'.",
        ),
    ] = "rich",
    verbose: Annotated[
        bool,
        typer.Option(
            "--verbose", "-v",
            help="Show evidence and recommendations even for passing probes.",
        ),
    ] = False,
    dry_run: Annotated[
        bool,
        typer.Option(
            "--dry-run",
            help="Validate configuration and list probes that would run, without sending requests.",
        ),
    ] = False,
    insecure: Annotated[
        bool,
        typer.Option(
            "--insecure",
            help="Skip TLS certificate verification (for self-signed endpoints). Use with caution.",
        ),
    ] = False,
) -> None:
    """Run a security audit against an LLM [bold cyan]ENDPOINT[/bold cyan].

    \b
    Examples:
      llm-audit audit https://api.openai.com/v1/chat/completions -k $OPENAI_KEY -m gpt-4o
      llm-audit audit http://localhost:11434/v1/chat/completions --model llama3
      llm-audit audit https://my-llm.example.com/chat --probes prompt_injection,jailbreak
    """
    if output_format not in ("rich", "json", "html"):
        render_error(f"Invalid format '{output_format}'. Choose 'rich', 'json', or 'html'.")
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
        output_format=output_format,  # type: ignore[typeddict-item]
        output_file=output_file,
        concurrency=concurrency,
        request_template=request_template,
        response_path=response_path,
        verbose=verbose,
        dry_run=dry_run,
        insecure=insecure,
    )

    if dry_run:
        probe_names = probe_list if probe_list else list(ALL_PROBES.keys())
        console.print("[bold cyan]llm-audit[/bold cyan] [dim]dry-run mode[/dim]\n")
        console.print(f"  [bold]Endpoint:[/bold]  {endpoint}")
        console.print(f"  [bold]Model:[/bold]     {model or '(not set)'}")
        console.print(f"  [bold]Timeout:[/bold]   {timeout}s")
        console.print(f"  [bold]Concurrency:[/bold] {concurrency}")
        console.print(f"  [bold]Format:[/bold]    {output_format}")
        console.print(f"  [bold]Insecure:[/bold]  {insecure}")
        if request_template:
            console.print(f"  [bold]Template:[/bold]  {request_template}")
        if response_path:
            console.print(f"  [bold]Resp path:[/bold] {response_path}")
        console.print(f"\n  [bold]Probes ({len(probe_names)}):[/bold]")
        for name in probe_names:
            cls = ALL_PROBES.get(name)
            if cls:
                console.print(f"    [cyan]{name}[/cyan] — {cls.owasp_id} — {cls.description}")
            else:
                console.print(f"    [red]{name}[/red] — unknown probe")
        console.print("\n[green]Configuration is valid. No requests were sent.[/green]")
        raise typer.Exit(code=0)

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
            elif output_format == "html":
                render_html(report, output=fh)
            else:
                render_report(report, verbose=verbose, output=fh)
        console.print(f"[dim]Report saved to[/dim] [bold cyan]{path.resolve()}[/bold cyan]")
    elif output_format == "json":
        render_json(report)
    elif output_format == "html":
        render_html(report)
    else:
        render_report(report, verbose=verbose)

    raise typer.Exit(code=1 if report["summary"]["failed"] > 0 else 0)


@app.command()
def list_probes() -> None:
    """List all available probes with their OWASP IDs and descriptions."""
    from rich import box
    from rich.table import Table


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
        table.add_row(probe_key, probe_cls.owasp_id, probe_cls.description)

    console.print(table)
