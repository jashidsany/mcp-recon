"""Undocumented capabilities.

Probes MCP spec-defined methods that are sometimes implemented but rarely
advertised. Success responses on unadvertised methods suggest the server
exposes more than its documented tool set.
"""

from __future__ import annotations

import time
from typing import Any

from mcp_recon.client import MCPClient
from mcp_recon.models import CheckResult, CheckStatus, Observation, ScanConfig, Severity

# Methods defined in the MCP spec that are *optional* on the server side.
# We intentionally omit `ping` because the spec requires every server to
# respond to it, so an unadvertised `ping` isn't a signal of anything.
# Same reasoning excludes `notifications/initialized` (a client-to-server
# notification with no response expected).
PROBE_METHODS = [
    "completion/complete",
    "logging/setLevel",
    "roots/list",
    "sampling/createMessage",
    "resources/templates/list",
    "resources/subscribe",
]


async def check_undocumented_capabilities(
    client: MCPClient,
    _config: ScanConfig,
    context: dict[str, Any],
) -> CheckResult:
    t0 = time.monotonic()
    advertised_caps = set(context.get("capabilities") or [])

    results: list[dict[str, Any]] = []
    surprising: list[dict[str, Any]] = []

    for method in PROBE_METHODS:
        try:
            ex = await client.rpc(method)
        except Exception as e:  # noqa: BLE001
            results.append({"method": method, "error": f"{type(e).__name__}: {e}"})
            continue

        entry: dict[str, Any] = {
            "method": method,
            "status": ex.status,
        }
        rj = ex.response_json or {}
        if "error" in rj:
            entry["jsonrpc_error_code"] = rj["error"].get("code")
            entry["jsonrpc_error_message"] = (rj["error"].get("message") or "")[:160]
        elif "result" in rj:
            entry["jsonrpc_result"] = True
            # Flag as surprising: we got a positive result from a method
            # the server didn't advertise in initialize capabilities.
            cap_root = method.split("/", 1)[0]
            if cap_root and cap_root not in advertised_caps and cap_root != "notifications":
                surprising.append(entry)
        results.append(entry)

    observations: list[Observation] = []
    if surprising:
        observations.append(
            Observation(
                title="server responds to methods outside its advertised capabilities",
                severity=Severity.LOW,
                summary=(
                    "The server returned successful JSON-RPC results for methods "
                    "whose capability root was not listed in the initialize "
                    "response. Undocumented methods may be debug endpoints, "
                    "legacy handlers, or accidental exposure."
                ),
                evidence={"methods": surprising, "advertised_capabilities": sorted(advertised_caps)},
                follow_up=(
                    "Invoke each surprising method directly and inspect the full "
                    "result. Check whether it returns data unavailable through "
                    "documented paths."
                ),
                see_also=[],
            )
        )

    return CheckResult(
        name="undocumented-capabilities",
        status=CheckStatus.RAN,
        duration_ms=int((time.monotonic() - t0) * 1000),
        data={"probed": PROBE_METHODS, "results": results},
        observations=observations,
    )
