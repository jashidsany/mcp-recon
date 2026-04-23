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


def _iso_now() -> str:
    return dt.datetime.now(tz=dt.timezone.utc).isoformat(timespec="seconds")


async def run_scan(config: ScanConfig) -> tuple[ScanReport, MCPClient]:
    started = _iso_now()
    t0 = time.monotonic()

    client = MCPClient(
        target=config.target,
        timeout=config.timeout_s,
        proxy=config.proxy,
        inter_request_delay_ms=config.inter_request_delay_ms,
        user_agent=config.user_agent,
        token=config.token,
        include_secrets=config.include_secrets,
    )

    context: dict[str, Any] = {}
    results: list[CheckResult] = []

    for name, fn in REGISTRY:
        try:
            res = await fn(client, config, context)
            # Expose select data into shared context for downstream checks
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

    finished = _iso_now()
    duration_ms = int((time.monotonic() - t0) * 1000)

    report = ScanReport(
        target=config.target,
        schema_version=SCHEMA_VERSION,
        tool_version=__version__,
        started_at=started,
        finished_at=finished,
        duration_ms=duration_ms,
        config=config.redacted(),
        checks=results,
    )
    return report, client


def write_artifacts(
    report: ScanReport,
    client: MCPClient,
    artifacts_dir: str,
) -> Path:
    base = Path(artifacts_dir)
    base.mkdir(parents=True, exist_ok=True)

    # Per-scan subdirectory: sanitized target + timestamp
    safe_target = (
        report.target.replace("://", "_")
        .replace("/", "_")
        .replace(":", "_")
        .strip("_")
    )
    ts = dt.datetime.now(tz=dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    scan_dir = base / f"{safe_target}_{ts}"
    scan_dir.mkdir(parents=True, exist_ok=True)

    # Report JSON
    (scan_dir / "report.json").write_text(
        json.dumps(report.to_dict(), indent=2, default=str),
        encoding="utf-8",
    )

    # Raw exchanges
    exchanges_path = scan_dir / "exchanges.json"
    exchanges_path.write_text(
        json.dumps([e.to_dict() for e in client.exchanges], indent=2, default=str),
        encoding="utf-8",
    )

    # Tighten permissions on the artifact directory (user-only read/write).
    try:
        os.chmod(scan_dir, 0o700)
        for f in scan_dir.iterdir():
            os.chmod(f, 0o600)
    except OSError:
        pass

    return scan_dir


def run_scan_sync(config: ScanConfig) -> tuple[ScanReport, MCPClient]:
    return asyncio.run(run_scan(config))
