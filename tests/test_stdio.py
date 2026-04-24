"""Integration tests for stdio transport."""

from __future__ import annotations

import sys
from pathlib import Path

from mcp_recon.checks import check_fingerprint, check_multi_request_pattern
from mcp_recon.client import MCPClient
from mcp_recon.models import CheckStatus, ScanConfig
from mcp_recon.runner import run_scan
from mcp_recon.transport import StdioTransport, TransportKind

STDIO_MOCK = str(Path(__file__).parent / "stdio_mock_server.py")


def _mock_cmd() -> str:
    return f"{sys.executable} {STDIO_MOCK}"


async def test_stdio_transport_roundtrip():
    t = StdioTransport(command=_mock_cmd(), inter_request_delay_ms=0)
    await t.start()
    try:
        ex = await t.rpc(
            "initialize",
            {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "test", "version": "0"},
            },
        )
        assert ex.error is None
        assert ex.payload is not None
        assert ex.payload["result"]["serverInfo"]["name"] == "StdioMock"
        # kind + response_json alias
        assert t.kind == TransportKind.STDIO
        assert ex.response_json == ex.payload
    finally:
        await t.stop()


async def test_stdio_fingerprint_check():
    t = StdioTransport(command=_mock_cmd(), inter_request_delay_ms=0)
    await t.start()
    try:
        client = MCPClient(target="stdio-test", transport=t)
        context: dict = {}
        result = await check_fingerprint(client, ScanConfig(target="stdio-test"), context)
        assert result.status == CheckStatus.RAN
        assert result.data["protocol_version"] == "2024-11-05"
        assert context["tool_names"] == ["ping", "fetch_doc"]
    finally:
        await t.stop()


async def test_stdio_multi_request_pattern_flags_url_tool():
    t = StdioTransport(command=_mock_cmd(), inter_request_delay_ms=0)
    await t.start()
    try:
        client = MCPClient(target="stdio-test", transport=t)
        context: dict = {}
        await check_fingerprint(client, ScanConfig(target="stdio-test"), context)
        result = await check_multi_request_pattern(
            client, ScanConfig(target="stdio-test"), context
        )
        assert result.status == CheckStatus.RAN
        names = {f["name"] for f in result.data["flagged"]}
        assert "fetch_doc" in names
    finally:
        await t.stop()


async def test_full_stdio_scan_marks_http_only_not_applicable():
    config = ScanConfig(
        target="stdio-mock",
        stdio_command=_mock_cmd(),
        inter_request_delay_ms=0,
    )
    report, client = await run_scan(config)

    names_by_status = {}
    for c in report.checks:
        names_by_status.setdefault(c.status, []).append(c.name)

    # HTTP-only checks must be SKIPPED_NOT_APPLICABLE in stdio mode.
    skipped = set(names_by_status.get(CheckStatus.SKIPPED_NOT_APPLICABLE, []))
    assert {"transport-hygiene", "cors-policy", "auth-header-hygiene",
            "discovery-consistency", "scope-binding"} <= skipped

    # Transport-agnostic checks should have run.
    ran = set(names_by_status.get(CheckStatus.RAN, []))
    assert {"fingerprint", "multi-request-pattern", "tool-description-anomalies",
            "undocumented-capabilities", "error-verbosity"} <= ran

    # Exit code should be 1 (multi-request-pattern flags the url-taking tool)
    # or 0 if it didn't. Either way not an error.
    assert report.exit_code in (0, 1)
