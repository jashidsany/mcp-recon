"""Minimal MCP-over-stdio mock server for tests.

Reads newline-delimited JSON-RPC 2.0 requests from stdin, writes responses
to stdout. Supports: initialize, tools/list, resources/list, prompts/list,
tools/call (echo).
"""

from __future__ import annotations

import json
import sys


def _send(msg: dict) -> None:
    sys.stdout.write(json.dumps(msg) + "\n")
    sys.stdout.flush()


def _handle(req: dict) -> dict:
    method = req.get("method")
    rid = req.get("id")
    if method == "initialize":
        return {
            "jsonrpc": "2.0",
            "id": rid,
            "result": {
                "protocolVersion": "2024-11-05",
                "serverInfo": {"name": "StdioMock", "version": "0.0.1"},
                "capabilities": {"tools": {}, "resources": {}},
            },
        }
    if method == "tools/list":
        return {
            "jsonrpc": "2.0",
            "id": rid,
            "result": {
                "tools": [
                    {
                        "name": "ping",
                        "description": "Ping the server.",
                        "inputSchema": {"properties": {"message": {"type": "string"}}},
                    },
                    {
                        "name": "fetch_doc",
                        "description": "Fetch a URL.",
                        "inputSchema": {
                            "properties": {"url": {"type": "string", "format": "uri"}}
                        },
                    },
                ]
            },
        }
    if method == "resources/list":
        return {"jsonrpc": "2.0", "id": rid, "result": {"resources": []}}
    if method == "prompts/list":
        return {"jsonrpc": "2.0", "id": rid, "result": {"prompts": []}}
    return {
        "jsonrpc": "2.0",
        "id": rid,
        "error": {"code": -32601, "message": "Method not found"},
    }


def main() -> None:
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except json.JSONDecodeError:
            _send({
                "jsonrpc": "2.0",
                "id": None,
                "error": {"code": -32700, "message": "Parse error"},
            })
            continue
        _send(_handle(req))


if __name__ == "__main__":
    main()
