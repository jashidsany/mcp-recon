"""MCP JSON-RPC client.

Wraps a Transport (HTTP or stdio) and exposes the MCP methods the checks
need. Stdio-only targets don't have a URL, so callers should handle that
via the transport.kind attribute.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from mcp_recon.transport import (
    Exchange,
    HttpExchange,
    HttpTransport,
    StdioExchange,
    StdioTransport,
    TransportKind,
)

# Re-export for backward compatibility with v0.1 callers.
__all__ = [
    "Exchange",
    "HttpExchange",
    "HttpTransport",
    "MCPClient",
    "StdioExchange",
    "StdioTransport",
    "TransportKind",
]


@dataclass
class MCPClient:
    """MCP client that speaks JSON-RPC 2.0 over a transport.

    Historically this was HTTP-only; v0.2 adds stdio support via the
    `transport` field. The legacy constructor (`target=...`) still works
    and continues to build an HTTP transport under the hood.
    """

    target: str = ""
    timeout: float = 30.0
    proxy: str | None = None
    inter_request_delay_ms: int = 100
    user_agent: str = "mcp-recon/0.2.0"
    token: str | None = None
    include_secrets: bool = False
    transport: HttpTransport | StdioTransport | None = None

    def __post_init__(self) -> None:
        # Legacy path: if no transport supplied, and target looks like a URL,
        # build an HttpTransport. This keeps the existing tests and callers
        # working unchanged.
        if self.transport is None:
            self.transport = HttpTransport(
                target=self.target,
                timeout=self.timeout,
                proxy=self.proxy,
                inter_request_delay_ms=self.inter_request_delay_ms,
                user_agent=self.user_agent,
                token=self.token,
                include_secrets=self.include_secrets,
            )

    @property
    def exchanges(self) -> list[Exchange]:
        assert self.transport is not None
        return self.transport.exchanges

    @property
    def kind(self) -> str:
        assert self.transport is not None
        return self.transport.kind

    # ------------------------------------------------------------------
    # Legacy HTTP-specific shims so existing checks keep working.
    # ------------------------------------------------------------------
    def _redact_headers(self, headers: dict[str, str]) -> dict[str, str]:
        if isinstance(self.transport, HttpTransport):
            return self.transport._redact_headers(headers)
        return dict(headers)

    def _build_headers(self, extra: dict[str, str] | None = None) -> dict[str, str]:
        if isinstance(self.transport, HttpTransport):
            return self.transport._build_headers(extra)
        return {}

    async def _request(
        self,
        method: str,
        url: str,
        headers: dict[str, str],
        body: Any | None = None,
    ) -> HttpExchange:
        if not isinstance(self.transport, HttpTransport):
            # Non-HTTP transport: synthesize a stub exchange so checks don't crash.
            return HttpExchange(
                ts=0.0,
                method=method,
                url=url,
                request_headers=headers,
                request_body=body,
                status=None,
                response_headers={},
                response_body_preview="",
                response_json=None,
                duration_ms=0,
                error="HTTP request called on a non-HTTP transport",
            )
        return await self.transport._request(method, url, headers, body)

    # ------------------------------------------------------------------
    # MCP protocol convenience methods (transport-agnostic)
    # ------------------------------------------------------------------
    # Pass-through for legacy test suite that calls MCPClient._parse_sse.
    @staticmethod
    def _parse_sse(body: str) -> Any:
        return HttpTransport._parse_sse(body)

    async def rpc(
        self,
        method: str,
        params: dict[str, Any] | None = None,
        rid: str | None = None,
    ) -> Exchange:
        assert self.transport is not None
        return await self.transport.rpc(method, params, rid)

    async def get(self, url: str) -> HttpExchange:
        if not isinstance(self.transport, HttpTransport):
            return HttpExchange(
                ts=0.0,
                method="GET",
                url=url,
                request_headers={},
                request_body=None,
                status=None,
                response_headers={},
                response_body_preview="",
                response_json=None,
                duration_ms=0,
                error="GET called on a non-HTTP transport",
            )
        return await self.transport.get(url)

    async def initialize(self) -> Exchange:
        return await self.rpc(
            "initialize",
            {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "mcp-recon", "version": "0.2.0"},
            },
        )

    async def tools_list(self) -> Exchange:
        return await self.rpc("tools/list")

    async def resources_list(self) -> Exchange:
        return await self.rpc("resources/list")

    async def prompts_list(self) -> Exchange:
        return await self.rpc("prompts/list")
