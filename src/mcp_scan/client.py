"""Minimal MCP-over-HTTP JSON-RPC 2.0 client.

Handles both `application/json` and `text/event-stream` responses because
MCP's Streamable HTTP transport may return either.

Records every request/response for artifact output.
"""

from __future__ import annotations

import asyncio
import json
import time
import uuid
from dataclasses import dataclass, field
from typing import Any

import httpx


@dataclass
class HttpExchange:
    """One recorded request/response pair."""

    ts: float
    method: str
    url: str
    request_headers: dict[str, str]
    request_body: Any
    status: int | None
    response_headers: dict[str, str]
    response_body_preview: str
    response_json: Any | None
    duration_ms: int
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "ts": self.ts,
            "method": self.method,
            "url": self.url,
            "request_headers": self.request_headers,
            "request_body": self.request_body,
            "status": self.status,
            "response_headers": self.response_headers,
            "response_body_preview": self.response_body_preview,
            "response_json": self.response_json,
            "duration_ms": self.duration_ms,
            "error": self.error,
        }


@dataclass
class MCPClient:
    """JSON-RPC 2.0 client for MCP over HTTP."""

    target: str
    timeout: float = 30.0
    proxy: str | None = None
    inter_request_delay_ms: int = 100
    user_agent: str = "mcp-scan/0.1.0"
    token: str | None = None
    include_secrets: bool = False
    exchanges: list[HttpExchange] = field(default_factory=list)

    _last_request_ts: float = 0.0

    async def _throttle(self) -> None:
        if self.inter_request_delay_ms <= 0:
            return
        delay = self.inter_request_delay_ms / 1000.0
        elapsed = time.monotonic() - self._last_request_ts
        if elapsed < delay:
            await asyncio.sleep(delay - elapsed)

    def _redact_headers(self, headers: dict[str, str]) -> dict[str, str]:
        if self.include_secrets:
            return dict(headers)
        redacted = {}
        for k, v in headers.items():
            if k.lower() in {"authorization", "cookie", "x-api-key", "x-shopify-access-token"}:
                redacted[k] = "[REDACTED]"
            else:
                redacted[k] = v
        return redacted

    def _build_headers(self, extra: dict[str, str] | None = None) -> dict[str, str]:
        h = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            "User-Agent": self.user_agent,
        }
        if self.token:
            h["Authorization"] = f"Bearer {self.token}"
        if extra:
            h.update(extra)
        return h

    async def _request(
        self,
        method: str,
        url: str,
        headers: dict[str, str],
        body: Any | None = None,
    ) -> HttpExchange:
        await self._throttle()
        t0 = time.monotonic()
        status: int | None = None
        resp_headers: dict[str, str] = {}
        resp_preview = ""
        resp_json: Any | None = None
        err: str | None = None
        try:
            async with httpx.AsyncClient(
                timeout=self.timeout,
                proxy=self.proxy,
                follow_redirects=True,
            ) as c:
                r = await c.request(
                    method,
                    url,
                    headers=headers,
                    content=json.dumps(body) if body is not None else None,
                )
            status = r.status_code
            resp_headers = dict(r.headers)
            body_text = r.text
            resp_preview = body_text[:4000]
            ct = r.headers.get("content-type", "")
            if "application/json" in ct:
                try:
                    resp_json = r.json()
                except ValueError:
                    resp_json = None
            elif "text/event-stream" in ct:
                resp_json = self._parse_sse(body_text)
        except Exception as e:
            err = f"{type(e).__name__}: {e}"
        finally:
            self._last_request_ts = time.monotonic()

        elapsed_ms = int((time.monotonic() - t0) * 1000)
        ex = HttpExchange(
            ts=time.time(),
            method=method,
            url=url,
            request_headers=self._redact_headers(headers),
            request_body=body,
            status=status,
            response_headers=resp_headers,
            response_body_preview=resp_preview,
            response_json=resp_json,
            duration_ms=elapsed_ms,
            error=err,
        )
        self.exchanges.append(ex)
        return ex

    @staticmethod
    def _parse_sse(body: str) -> Any | None:
        """Extract the first JSON payload from a text/event-stream body."""
        for line in body.splitlines():
            if line.startswith("data:"):
                payload = line[len("data:"):].strip()
                if not payload:
                    continue
                try:
                    return json.loads(payload)
                except ValueError:
                    continue
        return None

    async def rpc(
        self,
        method: str,
        params: dict[str, Any] | None = None,
        rid: str | None = None,
    ) -> HttpExchange:
        body = {
            "jsonrpc": "2.0",
            "id": rid or str(uuid.uuid4()),
            "method": method,
            "params": params or {},
        }
        return await self._request("POST", self.target, self._build_headers(), body)

    async def get(self, url: str) -> HttpExchange:
        return await self._request("GET", url, self._build_headers())

    async def initialize(self) -> HttpExchange:
        return await self.rpc(
            "initialize",
            {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "mcp-scan", "version": "0.1.0"},
            },
        )

    async def tools_list(self) -> HttpExchange:
        return await self.rpc("tools/list")

    async def resources_list(self) -> HttpExchange:
        return await self.rpc("resources/list")

    async def prompts_list(self) -> HttpExchange:
        return await self.rpc("prompts/list")
