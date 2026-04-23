"""A tiny HTTP-based MCP-ish mock server for integration tests.

Runs in a thread, binds to 127.0.0.1 on an ephemeral port, serves pre-set
JSON-RPC responses for a scripted sequence of requests.
"""

from __future__ import annotations

import json
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any


@dataclass
class MockServer:
    """Responds to one MCP endpoint plus .well-known documents."""

    mcp_path: str = "/api/mcp"
    rpc_handler: Callable[[dict[str, Any]], dict[str, Any]] | None = None
    well_known: dict[str, dict[str, Any]] = field(default_factory=dict)
    _server: HTTPServer | None = None
    _thread: threading.Thread | None = None
    _port: int = 0

    def start(self) -> int:
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802
                if self.path in outer.well_known:
                    body = json.dumps(outer.well_known[self.path]).encode()
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                    return
                self.send_response(404)
                self.end_headers()

            def do_POST(self):  # noqa: N802
                if self.path != outer.mcp_path:
                    self.send_response(404)
                    self.end_headers()
                    return
                length = int(self.headers.get("Content-Length", "0"))
                raw = self.rfile.read(length) if length else b""
                try:
                    req = json.loads(raw.decode())
                except ValueError:
                    self.send_response(400)
                    self.end_headers()
                    return
                default = {"jsonrpc": "2.0", "id": req.get("id"), "result": {}}
                resp = outer.rpc_handler(req) if outer.rpc_handler else default
                body = json.dumps(resp).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *_a):
                pass

        self._server = HTTPServer(("127.0.0.1", 0), Handler)
        self._port = self._server.server_address[1]
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self._port

    def stop(self) -> None:
        if self._server:
            self._server.shutdown()
            self._server.server_close()

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self._port}{self.mcp_path}"

    @property
    def origin(self) -> str:
        return f"http://127.0.0.1:{self._port}"
