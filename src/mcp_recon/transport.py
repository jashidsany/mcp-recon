"""Transport abstraction for MCP clients.

Two implementations:
- HttpTransport   - POST JSON-RPC to an HTTP endpoint (existing behaviour)
- StdioTransport  - spawn the MCP server as a subprocess, newline-delimited
                    JSON-RPC over stdin/stdout
"""

from __future__ import annotations

import asyncio
import json
import shlex
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Protocol

import httpx


class TransportKind:
    HTTP = "http"
    STDIO = "stdio"


@dataclass
class HttpExchange:
    """One recorded HTTP request/response pair."""

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
    transport: str = TransportKind.HTTP

    def to_dict(self) -> dict[str, Any]:
        return {
            "transport": self.transport,
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
class StdioExchange:
    """One recorded stdio RPC (line-delimited JSON over stdin/stdout).

    Exposes `response_json` and `status` aliases so checks written against
    HttpExchange don't need to branch on transport type.
    """

    ts: float
    direction: str  # "request" or "response"
    payload: Any
    duration_ms: int
    error: str | None = None
    transport: str = TransportKind.STDIO

    @property
    def response_json(self) -> Any:
        """Mirror the HttpExchange attribute so checks stay uniform."""
        return self.payload if self.direction == "response" else None

    @property
    def status(self) -> int | None:
        """No HTTP status for stdio; return 200 on success, None on error."""
        if self.error:
            return None
        return 200 if self.direction == "response" else None

    @property
    def response_body_preview(self) -> str:
        try:
            return json.dumps(self.payload)[:4000] if self.payload is not None else ""
        except (TypeError, ValueError):
            return str(self.payload)[:4000]

    @property
    def response_headers(self) -> dict[str, str]:
        return {}

    def to_dict(self) -> dict[str, Any]:
        return {
            "transport": self.transport,
            "ts": self.ts,
            "direction": self.direction,
            "payload": self.payload,
            "duration_ms": self.duration_ms,
            "error": self.error,
        }


Exchange = HttpExchange | StdioExchange


class Transport(Protocol):
    """A transport capable of carrying MCP JSON-RPC messages."""

    kind: str
    exchanges: list[Exchange]

    async def start(self) -> None:
        """Bring the transport up (e.g. spawn subprocess)."""

    async def stop(self) -> None:
        """Tear the transport down."""

    async def rpc(
        self,
        method: str,
        params: dict[str, Any] | None = None,
        rid: str | None = None,
    ) -> Exchange:
        """Send a JSON-RPC request and return the exchange record."""


# ---------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------

@dataclass
class HttpTransport:
    """POST JSON-RPC over HTTP. Existing v0.1 behaviour."""

    target: str
    timeout: float = 30.0
    proxy: str | None = None
    inter_request_delay_ms: int = 100
    user_agent: str = "mcp-recon/0.2.0"
    token: str | None = None
    include_secrets: bool = False
    exchanges: list[Exchange] = field(default_factory=list)
    kind: str = TransportKind.HTTP

    _last_request_ts: float = 0.0

    async def start(self) -> None:
        return None

    async def stop(self) -> None:
        return None

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
                redacted[k] = "[REDACTED]"  # noqa: S105 - marker, not a credential
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
        except Exception as e:  # noqa: BLE001
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


# ---------------------------------------------------------------------------
# stdio
# ---------------------------------------------------------------------------

@dataclass
class StdioTransport:
    """Spawn the MCP server as a subprocess and speak newline-delimited JSON-RPC."""

    command: str
    timeout: float = 30.0
    inter_request_delay_ms: int = 100
    env: dict[str, str] | None = None
    cwd: str | None = None
    exchanges: list[Exchange] = field(default_factory=list)
    kind: str = TransportKind.STDIO

    _proc: asyncio.subprocess.Process | None = None
    _stderr_chunks: list[str] = field(default_factory=list)
    _stderr_task: asyncio.Task | None = None
    _last_request_ts: float = 0.0

    async def start(self) -> None:
        argv = shlex.split(self.command)
        if not argv:
            raise ValueError("stdio command is empty")

        self._proc = await asyncio.create_subprocess_exec(
            *argv,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=self.env,
            cwd=self.cwd,
        )

        async def _drain_stderr() -> None:
            assert self._proc is not None
            assert self._proc.stderr is not None
            while True:
                line = await self._proc.stderr.readline()
                if not line:
                    return
                chunk = line.decode("utf-8", errors="replace").rstrip("\n")
                self._stderr_chunks.append(chunk)
                if len(self._stderr_chunks) > 500:
                    self._stderr_chunks = self._stderr_chunks[-500:]

        self._stderr_task = asyncio.create_task(_drain_stderr())

    async def stop(self) -> None:
        if self._proc is None:
            return
        try:
            if self._proc.stdin and not self._proc.stdin.is_closing():
                self._proc.stdin.close()
            try:
                await asyncio.wait_for(self._proc.wait(), timeout=2.0)
            except asyncio.TimeoutError:
                self._proc.terminate()
                try:
                    await asyncio.wait_for(self._proc.wait(), timeout=2.0)
                except asyncio.TimeoutError:
                    self._proc.kill()
        finally:
            if self._stderr_task:
                self._stderr_task.cancel()
                import contextlib
                with contextlib.suppress(asyncio.CancelledError, Exception):
                    await self._stderr_task

    async def _throttle(self) -> None:
        if self.inter_request_delay_ms <= 0:
            return
        delay = self.inter_request_delay_ms / 1000.0
        elapsed = time.monotonic() - self._last_request_ts
        if elapsed < delay:
            await asyncio.sleep(delay - elapsed)

    async def rpc(
        self,
        method: str,
        params: dict[str, Any] | None = None,
        rid: str | None = None,
    ) -> StdioExchange:
        await self._throttle()
        if self._proc is None or self._proc.stdin is None or self._proc.stdout is None:
            return StdioExchange(
                ts=time.time(),
                direction="request",
                payload={"method": method, "params": params},
                duration_ms=0,
                error="transport not started",
            )

        body = {
            "jsonrpc": "2.0",
            "id": rid or str(uuid.uuid4()),
            "method": method,
            "params": params or {},
        }
        expected_id = body["id"]

        # Log the outgoing request
        self.exchanges.append(StdioExchange(
            ts=time.time(),
            direction="request",
            payload=body,
            duration_ms=0,
        ))

        t0 = time.monotonic()
        err: str | None = None
        response: Any | None = None

        try:
            line = (json.dumps(body) + "\n").encode("utf-8")
            self._proc.stdin.write(line)
            await self._proc.stdin.drain()

            # Read lines until we get a response whose id matches ours
            # (notifications from server are dropped but recorded)
            while True:
                raw = await asyncio.wait_for(
                    self._proc.stdout.readline(),
                    timeout=self.timeout,
                )
                if not raw:
                    err = "stdout closed (server exited)"
                    break
                text = raw.decode("utf-8", errors="replace").rstrip("\n")
                if not text:
                    continue
                try:
                    msg = json.loads(text)
                except json.JSONDecodeError as e:
                    self.exchanges.append(StdioExchange(
                        ts=time.time(),
                        direction="response",
                        payload={"raw": text, "parse_error": str(e)},
                        duration_ms=int((time.monotonic() - t0) * 1000),
                        error="non-json line on stdout",
                    ))
                    continue

                if isinstance(msg, dict) and msg.get("id") == expected_id:
                    response = msg
                    break
                # Unrelated message (notification, mismatched id) - record but keep reading
                self.exchanges.append(StdioExchange(
                    ts=time.time(),
                    direction="response",
                    payload=msg,
                    duration_ms=0,
                    error="out-of-band message",
                ))
        except asyncio.TimeoutError:
            err = f"no response within {self.timeout}s"
        except (BrokenPipeError, ConnectionResetError) as e:
            err = f"{type(e).__name__}: {e}"
        except Exception as e:  # noqa: BLE001
            err = f"{type(e).__name__}: {e}"
        finally:
            self._last_request_ts = time.monotonic()

        elapsed_ms = int((time.monotonic() - t0) * 1000)
        ex = StdioExchange(
            ts=time.time(),
            direction="response",
            payload=response,
            duration_ms=elapsed_ms,
            error=err,
        )
        self.exchanges.append(ex)
        return ex

    def stderr_tail(self) -> str:
        return "\n".join(self._stderr_chunks[-50:])
