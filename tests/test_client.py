"""Unit tests for the MCP client and SSE parsing."""

from __future__ import annotations

from mcp_scan.client import MCPClient


def test_parse_sse_extracts_json_payload():
    body = (
        "event: message\n"
        'data: {"jsonrpc":"2.0","id":"1","result":{"ok":true}}\n'
        "\n"
    )
    parsed = MCPClient._parse_sse(body)
    assert parsed == {"jsonrpc": "2.0", "id": "1", "result": {"ok": True}}


def test_parse_sse_returns_none_on_garbage():
    body = "event: heartbeat\ndata: not-json\n\n"
    assert MCPClient._parse_sse(body) is None


def test_redact_headers_hides_auth():
    c = MCPClient(target="http://example", include_secrets=False)
    out = c._redact_headers({"Authorization": "Bearer secret", "X-Trace": "keep"})
    assert out["Authorization"] == "[REDACTED]"
    assert out["X-Trace"] == "keep"


def test_redact_headers_honors_include_secrets():
    c = MCPClient(target="http://example", include_secrets=True)
    out = c._redact_headers({"Authorization": "Bearer secret"})
    assert out["Authorization"] == "Bearer secret"


def test_build_headers_includes_token():
    c = MCPClient(target="http://example", token="abc123")
    h = c._build_headers()
    assert h["Authorization"] == "Bearer abc123"


def test_build_headers_no_token():
    c = MCPClient(target="http://example")
    h = c._build_headers()
    assert "Authorization" not in h
