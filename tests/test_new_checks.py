"""Tests for the transport-hygiene, cors-policy, auth-header-hygiene checks
and the tool-name-anomaly extension."""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

from mcp_recon.checks import (
    check_auth_header_hygiene,
    check_cors_policy,
    check_tool_description_anomalies,
    check_transport_hygiene,
)
from mcp_recon.client import MCPClient
from mcp_recon.models import CheckStatus, ScanConfig, Severity


def _make_server(handler_cls):
    s = HTTPServer(("127.0.0.1", 0), handler_cls)
    t = threading.Thread(target=s.serve_forever, daemon=True)
    t.start()
    return s


async def test_transport_hygiene_flags_http_non_loopback():
    """Scheme check: flag HTTP on non-loopback. Simulate by passing a non-loopback hostname."""

    class NoopHandler(BaseHTTPRequestHandler):
        def do_POST(self):
            self.send_response(200)
            self.end_headers()
        def do_GET(self):
            self.send_response(405)
            self.end_headers()
        def do_OPTIONS(self):
            self.send_response(405)
            self.end_headers()
        def log_message(self, *_a): pass

    s = _make_server(NoopHandler)
    s.server_address[1]
    try:
        # Build a spoofed target using an IP literal that isn't loopback.
        # Since the hostname check rejects loopback literally, pass a non-loopback IP
        # that also won't actually connect; we bypass the connect by mocking it.
        client = MCPClient(target="http://10.0.0.99/api/mcp", inter_request_delay_ms=0, timeout=1)
        result = await check_transport_hygiene(client, ScanConfig(target=client.target), {})
        titles = {o.title for o in result.observations}
        assert "MCP endpoint served over plaintext HTTP" in titles
    finally:
        s.shutdown()
        s.server_close()


async def test_transport_hygiene_no_flag_on_loopback():
    """HTTP on loopback is fine for local test servers."""
    client = MCPClient(target="http://127.0.0.1:65535/api/mcp", inter_request_delay_ms=0, timeout=1)
    result = await check_transport_hygiene(client, ScanConfig(target=client.target), {})
    titles = {o.title for o in result.observations}
    assert "MCP endpoint served over plaintext HTTP" not in titles


async def test_cors_policy_flags_wildcard_with_credentials():
    class CorsHandler(BaseHTTPRequestHandler):
        def do_OPTIONS(self):
            self.send_response(200)
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Allow-Credentials", "true")
            self.end_headers()
        def do_POST(self):
            self.send_response(200)
            self.end_headers()
        def log_message(self, *_a): pass

    s = _make_server(CorsHandler)
    port = s.server_address[1]
    try:
        client = MCPClient(target=f"http://127.0.0.1:{port}/api/mcp", inter_request_delay_ms=0, timeout=2)
        result = await check_cors_policy(client, ScanConfig(target=client.target), {})
        assert result.status == CheckStatus.RAN
        titles = {o.title for o in result.observations}
        assert "CORS allows wildcard origin with credentials" in titles
    finally:
        s.shutdown()
        s.server_close()


async def test_cors_policy_flags_reflected_origin():
    class CorsReflectHandler(BaseHTTPRequestHandler):
        def do_OPTIONS(self):
            origin = self.headers.get("Origin", "")
            self.send_response(200)
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Access-Control-Allow-Credentials", "true")
            self.end_headers()
        def do_POST(self):
            self.send_response(200)
            self.end_headers()
        def log_message(self, *_a): pass

    s = _make_server(CorsReflectHandler)
    port = s.server_address[1]
    try:
        client = MCPClient(target=f"http://127.0.0.1:{port}/api/mcp", inter_request_delay_ms=0, timeout=2)
        result = await check_cors_policy(client, ScanConfig(target=client.target), {})
        titles = {o.title for o in result.observations}
        assert "CORS echoes attacker Origin with credentials" in titles
    finally:
        s.shutdown()
        s.server_close()


async def test_cors_policy_flags_null_origin():
    class CorsNullHandler(BaseHTTPRequestHandler):
        def do_OPTIONS(self):
            self.send_response(200)
            self.send_header("Access-Control-Allow-Origin", "null")
            self.end_headers()
        def do_POST(self):
            self.send_response(200)
            self.end_headers()
        def log_message(self, *_a): pass

    s = _make_server(CorsNullHandler)
    port = s.server_address[1]
    try:
        client = MCPClient(target=f"http://127.0.0.1:{port}/api/mcp", inter_request_delay_ms=0, timeout=2)
        result = await check_cors_policy(client, ScanConfig(target=client.target), {})
        titles = {o.title for o in result.observations}
        assert "CORS allows 'null' origin" in titles
    finally:
        s.shutdown()
        s.server_close()


async def test_auth_header_hygiene_skips_when_no_challenge():
    class NoChallengeHandler(BaseHTTPRequestHandler):
        def do_POST(self):
            body = json.dumps({"jsonrpc":"2.0","id":"1","result":{"tools":[]}}).encode()
            self.send_response(200)
            self.send_header("Content-Type","application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        def log_message(self, *_a): pass

    s = _make_server(NoChallengeHandler)
    port = s.server_address[1]
    try:
        client = MCPClient(target=f"http://127.0.0.1:{port}/api/mcp", inter_request_delay_ms=0, timeout=2)
        result = await check_auth_header_hygiene(client, ScanConfig(target=client.target), {})
        assert result.status == CheckStatus.SKIPPED_NOT_APPLICABLE
    finally:
        s.shutdown()
        s.server_close()


async def test_auth_header_hygiene_flags_infra_hints():
    class LeakyChallengeHandler(BaseHTTPRequestHandler):
        def do_POST(self):
            self.send_response(401)
            self.send_header("WWW-Authenticate", 'Bearer realm="internal-k8s-cluster-prod", error="invalid_token", error_description="Traceback in /opt/app/auth.py"')
            self.end_headers()
        def log_message(self, *_a): pass

    s = _make_server(LeakyChallengeHandler)
    port = s.server_address[1]
    try:
        client = MCPClient(target=f"http://127.0.0.1:{port}/api/mcp", inter_request_delay_ms=0, timeout=2)
        result = await check_auth_header_hygiene(client, ScanConfig(target=client.target), {})
        assert result.status == CheckStatus.RAN
        titles = {o.title for o in result.observations}
        # Should flag both infra hints and filesystem path leak
        assert any("infrastructure hints" in t for t in titles)
        assert any("filesystem path" in t for t in titles)
    finally:
        s.shutdown()
        s.server_close()


async def test_tool_name_anomaly_flags_zero_width():
    """Tool name containing zero-width char - stronger than description."""
    context = {
        "tools_full": [
            {
                "name": "search\u200b",  # zero-width space in name
                "description": "Normal search.",
                "inputSchema": {},
            }
        ],
    }
    result = await check_tool_description_anomalies(
        MCPClient(target="http://unused"),
        ScanConfig(target="http://unused"),
        context,
    )
    titles = {o.title for o in result.observations}
    assert any("suspicious characters in tool name" in t for t in titles)
    # Name anomaly should be flagged at Medium, not Low
    name_obs = next(o for o in result.observations if "tool name" in o.title)
    assert name_obs.severity == Severity.MEDIUM
