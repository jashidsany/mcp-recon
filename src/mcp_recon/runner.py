"""Scan runner: orchestrate checks, assemble ScanReport, write artifacts."""

from __future__ import annotations

import asyncio
import datetime as dt
import json
import os
import time
from pathlib import Path
from typing import Any

from mcp_recon import SCHEMA_VERSION, __version__
from mcp_recon.checks import REGISTRY
from mcp_recon.client import MCPClient
from mcp_recon.models import CheckResult, CheckStatus, ScanConfig, ScanReport
from mcp_recon.transport import HttpTransport, StdioTransport

# Checks that require an HTTP transport. When the target is spawned via
# stdio, these are recorded as SKIPPED_NOT_APPLICABLE with a short note.
HTTP_ONLY_CHECKS = {
    "transport-hygiene",
    "cors-policy",
    "auth-header-hygiene",
    "discovery-consistency",
    "scope-binding",
}


def _iso_now() -> str:
    return dt.datetime.now(tz=dt.timezone.utc).isoformat(timespec="seconds")


async def run_scan(config: ScanConfig) -> tuple[ScanReport, MCPClient]:
    started = _iso_now()
    t0 = time.monotonic()

    if config.stdio_command:
        transport = StdioTransport(
            command=config.stdio_command,
            timeout=config.timeout_s,
            inter_request_delay_ms=config.inter_request_delay_ms,
        )
    else:
        transport = HttpTransport(
            target=config.target,
            timeout=config.timeout_s,
            proxy=config.proxy,
            inter_request_delay_ms=config.inter_request_delay_ms,
            user_agent=config.user_agent,
            token=config.token,
            include_secrets=config.include_secrets,
        )

    client = MCPClient(
        target=config.target,
        timeout=config.timeout_s,
        proxy=config.proxy,
        inter_request_delay_ms=config.inter_request_delay_ms,
        user_agent=config.user_agent,
        token=config.token,
        include_secrets=config.include_secrets,
        transport=transport,
    )

    context: dict[str, Any] = {}
    results: list[CheckResult] = []

    await transport.start()
    try:
        for name, fn in REGISTRY:
            if config.stdio_command and name in HTTP_ONLY_CHECKS:
                results.append(CheckResult(
                    name=name,
                    status=CheckStatus.SKIPPED_NOT_APPLICABLE,
                    duration_ms=0,
                    notes=["http-only check; not applicable when running a stdio target"],
                ))
                continue
            try:
                res = await fn(client, config, context)
                if name == "fingerprint" and res.status == CheckStatus.RAN:
                    context["capabilities"] = res.data.get("capabilities") or []
                results.append(res)
            except Exception as e:  # noqa: BLE001
                results.append(CheckResult(
                    name=name,
                    status=CheckStatus.ERRORED,
                    duration_ms=0,
                    error=f"{type(e).__name__}: {e}",
                ))
    finally:
        await transport.stop()

    finished = _iso_now()
    duration_ms = int((time.monotonic() - t0) * 1000)

    report = ScanReport(
        target=_display_target(config),
        schema_version=SCHEMA_VERSION,
        tool_version=__version__,
        started_at=started,
        finished_at=finished,
        duration_ms=duration_ms,
        config=config.redacted(),
        checks=results,
    )
    return report, client


def _display_target(config: ScanConfig) -> str:
    if config.stdio_command:
        return config.target or f"stdio:{config.stdio_command}"
    return config.target


def write_artifacts(
    report: ScanReport,
    client: MCPClient,
    artifacts_dir: str,
) -> Path:
    base = Path(artifacts_dir)
    base.mkdir(parents=True, exist_ok=True)

    safe_target = (
        report.target.replace("://", "_")
        .replace("/", "_")
        .replace(":", "_")
        .replace(" ", "_")
        .strip("_")
    )
    # shell-friendly cap on directory length
    if len(safe_target) > 80:
        safe_target = safe_target[:80]

    ts = dt.datetime.now(tz=dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    scan_dir = base / f"{safe_target}_{ts}"
    scan_dir.mkdir(parents=True, exist_ok=True)

    (scan_dir / "report.json").write_text(
        json.dumps(report.to_dict(), indent=2, default=str),
        encoding="utf-8",
    )

    exchanges_path = scan_dir / "exchanges.json"
    exchanges_path.write_text(
        json.dumps([e.to_dict() for e in client.exchanges], indent=2, default=str),
        encoding="utf-8",
    )

    # Capture stderr tail for stdio targets - often contains the server's
    # startup banner and any warnings, which are useful for triage.
    from mcp_recon.transport import StdioTransport as _StdioT
    if isinstance(client.transport, _StdioT):
        tail = client.transport.stderr_tail()
        if tail:
            (scan_dir / "server_stderr.txt").write_text(tail, encoding="utf-8")

    try:
        os.chmod(scan_dir, 0o700)
        for f in scan_dir.iterdir():
            os.chmod(f, 0o600)
    except OSError:
        pass

    return scan_dir


def run_scan_sync(config: ScanConfig) -> tuple[ScanReport, MCPClient]:
    return asyncio.run(run_scan(config))
