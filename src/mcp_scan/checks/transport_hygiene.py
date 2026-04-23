"""Transport hygiene.

Flags insecure schemes (HTTP instead of HTTPS) and unexpected responses
to non-POST HTTP methods against the MCP endpoint. MCP is JSON-RPC over
POST; success responses on other methods suggest debug surfaces or
misconfigured routing.
"""

from __future__ import annotations

import time
from typing import Any
from urllib.parse import urlparse

from mcp_scan.client import MCPClient
from mcp_scan.models import CheckResult, CheckStatus, Observation, ScanConfig, Severity

PROBE_METHODS = ["GET", "OPTIONS", "DELETE", "PUT", "PATCH"]


async def check_transport_hygiene(
    client: MCPClient,
    _config: ScanConfig,
    _context: dict[str, Any],
) -> CheckResult:
    t0 = time.monotonic()
    observations: list[Observation] = []
    data: dict[str, Any] = {}

    parsed = urlparse(client.target)

    # Scheme check
    data["scheme"] = parsed.scheme
    if parsed.scheme == "http" and parsed.hostname not in {"127.0.0.1", "localhost", "::1"}:
        observations.append(
            Observation(
                title="MCP endpoint served over plaintext HTTP",
                severity=Severity.MEDIUM,
                summary=(
                    "The MCP endpoint is reachable over plaintext HTTP on a "
                    "non-loopback host. Requests, responses, and any OAuth "
                    "tokens carried in Authorization headers traverse the "
                    "network unencrypted."
                ),
                evidence={"target": client.target, "scheme": parsed.scheme},
                follow_up=(
                    "Confirm the endpoint also serves HTTPS and redirect "
                    "plaintext traffic. Inspect the response to a plain "
                    "curl -v to see if the server even issues a redirect."
                ),
                see_also=["https://cwe.mitre.org/data/definitions/319.html"],
            )
        )

    # HTTP method probes (read-only methods only; no PATCH/PUT/DELETE to be safe)
    method_results: list[dict[str, Any]] = []
    unexpected_success: list[dict[str, Any]] = []
    for method in ["GET", "OPTIONS"]:
        try:
            ex = await client._request(method, client.target, client._build_headers())
        except Exception as e:  # noqa: BLE001
            method_results.append({"method": method, "error": f"{type(e).__name__}: {e}"})
            continue
        entry = {
            "method": method,
            "status": ex.status,
            "server": ex.response_headers.get("server") or ex.response_headers.get("Server"),
        }
        method_results.append(entry)
        # 200 on GET of an MCP endpoint is usually unexpected.
        if ex.status == 200 and method == "GET":
            body_has_content = bool(ex.response_body_preview.strip())
            looks_like_jsonrpc = "jsonrpc" in ex.response_body_preview[:200]
            if body_has_content and not looks_like_jsonrpc:
                unexpected_success.append(entry)

    data["method_probes"] = method_results

    if unexpected_success:
        observations.append(
            Observation(
                title="non-JSON response to GET on MCP endpoint",
                severity=Severity.LOW,
                summary=(
                    "GET on the MCP endpoint returned 200 with non-JSON-RPC "
                    "content. May indicate a routing misconfiguration, a "
                    "leaked admin/status page, or debug surface at the same "
                    "path."
                ),
                evidence={"method_responses": unexpected_success},
                follow_up=f"Manually inspect: curl -i {client.target}",
                see_also=[],
            )
        )

    # Server header surface
    server_hdr = None
    for entry in method_results:
        if entry.get("server"):
            server_hdr = entry["server"]
            break
    if server_hdr:
        data["server_header"] = server_hdr

    return CheckResult(
        name="transport-hygiene",
        status=CheckStatus.RAN,
        duration_ms=int((time.monotonic() - t0) * 1000),
        data=data,
        observations=observations,
    )
