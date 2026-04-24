"""CLI entrypoint using typer."""

from __future__ import annotations

import os
import sys

import typer
from rich.console import Console

from mcp_recon import __version__
from mcp_recon.models import ScanConfig
from mcp_recon.report import render_human, render_json, render_markdown
from mcp_recon.runner import run_scan_sync, write_artifacts

app = typer.Typer(
    help=(
        "mcp-recon: reconnaissance scanner for Model Context Protocol servers.\n\n"
        "Only run against servers you own or have explicit authorization to test. "
        "Unauthorized scanning may violate computer misuse laws in your jurisdiction."
    ),
    add_completion=False,
    no_args_is_help=True,
)

ERR = Console(stderr=True)


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"mcp-recon {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    _version: bool = typer.Option(
        False, "--version", callback=_version_callback, is_eager=True, help="Show version and exit."
    ),
) -> None:
    pass


@app.command()
def scan(
    target: str = typer.Argument(None, help="MCP endpoint URL for HTTP, or a free-form label when --stdio is set"),
    stdio: str = typer.Option(None, "--stdio", help="Run the MCP server as a subprocess (stdio transport). Provide the command line, e.g. --stdio 'uvx mcp-server-fetch'."),
    output: str = typer.Option("human", "--output", "-o", help="Output format: human, json, markdown"),
    token: str = typer.Option(None, "--token", help="OAuth access token for scope-binding probe (or MCP_RECON_TOKEN env var). HTTP mode only."),
    proxy: str = typer.Option(None, "--proxy", help="HTTP proxy URL (overrides HTTPS_PROXY env). HTTP mode only."),
    timeout: float = typer.Option(30.0, "--timeout", help="Per-request timeout in seconds"),
    inter_request_delay_ms: int = typer.Option(100, "--delay-ms", help="Delay between requests in ms (default 100; use 0 for --aggressive)"),
    aggressive: bool = typer.Option(False, "--aggressive", help="Remove inter-request delay (equivalent to --delay-ms 0)"),
    artifacts_dir: str = typer.Option("./mcp-recon-artifacts", "--artifacts", help="Directory to save raw request/response artifacts"),
    no_artifacts: bool = typer.Option(False, "--no-artifacts", help="Skip writing raw artifact files"),
    include_secrets: bool = typer.Option(False, "--include-secrets", help="Do not redact Authorization / Cookie / API key headers in artifacts (USE WITH CAUTION)"),
) -> None:
    """Scan one MCP server over HTTP or stdio."""
    resolved_token = token or os.environ.get("MCP_RECON_TOKEN")
    resolved_proxy = proxy or os.environ.get("HTTPS_PROXY") or os.environ.get("HTTP_PROXY")

    if not stdio and not target:
        ERR.print("[red]error:[/red] either a URL target or --stdio \"command\" is required.")
        raise typer.Exit(code=3)

    # When using --stdio, target is an optional label. Default to the first
    # token of the command so artifacts have a sensible directory name.
    if stdio and not target:
        target = stdio.split()[0] if stdio.split() else "stdio-target"

    delay = 0 if aggressive else inter_request_delay_ms

    config = ScanConfig(
        target=target,
        timeout_s=timeout,
        inter_request_delay_ms=delay,
        proxy=resolved_proxy,
        token=resolved_token,
        include_secrets=include_secrets,
        stdio_command=stdio,
    )

    try:
        report, client = run_scan_sync(config)
    except KeyboardInterrupt:
        ERR.print("[yellow]interrupted[/yellow]")
        raise typer.Exit(code=130) from None
    except Exception as e:  # noqa: BLE001
        ERR.print(f"[red]scan failed:[/red] {type(e).__name__}: {e}")
        raise typer.Exit(code=2) from None

    if not no_artifacts:
        try:
            scan_dir = write_artifacts(report, client, artifacts_dir)
            ERR.print(f"[dim]artifacts: {scan_dir}[/dim]")
        except Exception as e:  # noqa: BLE001
            ERR.print(f"[yellow]warning:[/yellow] could not write artifacts: {e}")

    if output == "json":
        sys.stdout.write(render_json(report))
        sys.stdout.write("\n")
    elif output == "markdown":
        sys.stdout.write(render_markdown(report))
        sys.stdout.write("\n")
    else:
        sys.stdout.write(render_human(report))

    raise typer.Exit(code=report.exit_code)
