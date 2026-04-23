"""Integration tests for individual checks against the mock MCP server."""

from __future__ import annotations

import pytest

from mcp_recon.checks import (
    check_discovery_consistency,
    check_error_verbosity,
    check_fingerprint,
    check_multi_request_pattern,
    check_tool_description_anomalies,
)
from mcp_recon.client import MCPClient
from mcp_recon.models import CheckStatus, ScanConfig, Severity

from .mock_server import MockServer


def _rpc_handler_for_success():
    def handler(req: dict) -> dict:
        rid = req.get("id")
        method = req.get("method")
        if method == "initialize":
            return {
                "jsonrpc": "2.0", "id": rid,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "serverInfo": {"name": "MockMCP", "version": "0.0.1"},
                    "capabilities": {"tools": {}, "resources": {}},
                },
            }
        if method == "tools/list":
            return {
                "jsonrpc": "2.0", "id": rid,
                "result": {"tools": [
                    {
                        "name": "search",
                        "description": "Search the catalog.",
                        "inputSchema": {"properties": {"query": {"type": "string"}}},
                    },
                    {
                        "name": "fetch_doc",
                        "description": "Fetch a URL and return contents.",
                        "inputSchema": {"properties": {"url": {"type": "string", "format": "uri"}}},
                    },
                ]},
            }
        if method == "resources/list":
            return {"jsonrpc": "2.0", "id": rid, "result": {"resources": []}}
        if method == "prompts/list":
            return {"jsonrpc": "2.0", "id": rid, "result": {"prompts": []}}
        # unknown method -> JSON-RPC error
        return {
            "jsonrpc": "2.0", "id": rid,
            "error": {"code": -32601, "message": "Method not found"},
        }
    return handler


@pytest.fixture
def mock_server():
    s = MockServer(rpc_handler=_rpc_handler_for_success())
    s.start()
    try:
        yield s
    finally:
        s.stop()


async def _make_client(server: MockServer) -> MCPClient:
    return MCPClient(target=server.url, inter_request_delay_ms=0)


async def test_fingerprint_detects_tools(mock_server):
    client = await _make_client(mock_server)
    context: dict = {}
    result = await check_fingerprint(client, ScanConfig(target=mock_server.url), context)
    assert result.status == CheckStatus.RAN
    assert result.data["protocol_version"] == "2024-11-05"
    assert {"tools", "resources"} <= set(result.data["capabilities"])
    assert len(result.data["tools"]) == 2
    assert context["tool_names"] == ["search", "fetch_doc"]


async def test_multi_request_pattern_flags_url_tool(mock_server):
    client = await _make_client(mock_server)
    context: dict = {}
    await check_fingerprint(client, ScanConfig(target=mock_server.url), context)
    result = await check_multi_request_pattern(
        client, ScanConfig(target=mock_server.url), context
    )
    assert result.status == CheckStatus.RAN
    assert any(f["name"] == "fetch_doc" for f in result.data["flagged"])
    assert len(result.observations) == 1
    assert result.observations[0].severity == Severity.LOW


async def test_tool_description_anomalies_clean(mock_server):
    client = await _make_client(mock_server)
    context: dict = {}
    await check_fingerprint(client, ScanConfig(target=mock_server.url), context)
    result = await check_tool_description_anomalies(
        client, ScanConfig(target=mock_server.url), context
    )
    assert result.status == CheckStatus.RAN
    # No control chars in clean fixture
    assert result.observations == []


async def test_tool_description_anomalies_flags_zero_width():
    """Synthetic context with a tool containing a zero-width char."""
    context = {
        "tools_full": [
            {
                "name": "trojan",
                "description": "Looks harmless.\u200b secretly does more.",
                "inputSchema": {},
            }
        ],
    }
    result = await check_tool_description_anomalies(
        MCPClient(target="http://unused"),
        ScanConfig(target="http://unused"),
        context,
    )
    assert any(o.title.startswith("suspicious characters") for o in result.observations)


async def test_error_verbosity_flags_path_leak():
    """Mock a server that leaks paths in error responses."""
    def handler(req):
        return {
            "jsonrpc": "2.0", "id": req.get("id"),
            "error": {"code": -32000, "message": "File not found at /home/deploy/app/server.py"},
        }
    s = MockServer(rpc_handler=handler)
    s.start()
    try:
        client = MCPClient(target=s.url, inter_request_delay_ms=0)
        result = await check_error_verbosity(client, ScanConfig(target=s.url), {})
        assert result.status == CheckStatus.RAN
        titles = {o.title for o in result.observations}
        assert "filesystem paths leaked in error response" in titles
    finally:
        s.stop()


async def test_discovery_consistency_detects_mismatch():
    """Mock a server with two well-known docs that disagree on scopes_supported."""
    s = MockServer(
        rpc_handler=_rpc_handler_for_success(),
        well_known={
            "/.well-known/oauth-authorization-server": {
                "scopes_supported": ["read", "write", "admin"],
            },
            "/.well-known/openid-configuration": {
                "scopes_supported": ["openid", "offline"],
            },
        },
    )
    s.start()
    try:
        client = MCPClient(target=s.url, inter_request_delay_ms=0)
        result = await check_discovery_consistency(client, ScanConfig(target=s.url), {})
        assert result.status == CheckStatus.RAN
        titles = {o.title for o in result.observations}
        assert "discovery documents disagree on scopes_supported" in titles
    finally:
        s.stop()


async def test_discovery_consistency_clean_when_aligned():
    s = MockServer(
        rpc_handler=_rpc_handler_for_success(),
        well_known={
            "/.well-known/oauth-authorization-server": {
                "scopes_supported": ["read", "write"],
            },
            "/.well-known/openid-configuration": {
                "scopes_supported": ["read", "write"],
            },
        },
    )
    s.start()
    try:
        client = MCPClient(target=s.url, inter_request_delay_ms=0)
        result = await check_discovery_consistency(client, ScanConfig(target=s.url), {})
        assert result.status == CheckStatus.RAN
        assert not result.observations
    finally:
        s.stop()
