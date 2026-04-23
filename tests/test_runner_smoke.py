"""End-to-end smoke test: run the full scan against the mock server."""

from __future__ import annotations

import pytest

from mcp_scan.models import ScanConfig
from mcp_scan.runner import run_scan

from .mock_server import MockServer
from .test_checks import _rpc_handler_for_success


@pytest.fixture
def mock_server():
    s = MockServer(rpc_handler=_rpc_handler_for_success())
    s.start()
    try:
        yield s
    finally:
        s.stop()


async def test_full_scan_runs(mock_server):
    report, client = await run_scan(ScanConfig(target=mock_server.url, inter_request_delay_ms=0))
    names = {c.name for c in report.checks}
    assert {
        "fingerprint",
        "transport-hygiene",
        "cors-policy",
        "auth-header-hygiene",
        "discovery-consistency",
        "error-verbosity",
        "tool-description-anomalies",
        "multi-request-pattern",
        "undocumented-capabilities",
        "scope-binding",
    } <= names

    assert report.exit_code in (0, 1, 2)
    assert client.exchanges  # recorded at least one exchange
