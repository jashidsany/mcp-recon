"""Multi-outbound-request pattern.

Identifies tools whose input schema suggests a URL argument. Such tools
often trigger N > 1 outbound requests per invocation (e.g. a pre-fetch
robots.txt check + the main fetch). If those requests resolve DNS
independently, a rebinding attacker can route them to different IPs.

This check does NOT actively probe by calling the tool. It flags the
architectural risk based on static inspection of tool schemas. Active
timing-based confirmation is left to the operator as a manual follow-up.
"""

from __future__ import annotations

import re
import time
from typing import Any

from mcp_recon.client import MCPClient
from mcp_recon.models import CheckResult, CheckStatus, Observation, ScanConfig, Severity

URL_PARAM_HINTS = re.compile(r"\b(url|uri|link|endpoint|fetch|source|target|webhook|callback)\b", re.I)


def _scan_schema_for_url_params(schema: dict[str, Any] | None) -> list[str]:
    if not isinstance(schema, dict):
        return []
    found: list[str] = []
    props = schema.get("properties") or {}
    if isinstance(props, dict):
        for name, spec in props.items():
            name_hit = URL_PARAM_HINTS.search(name or "")
            if name_hit:
                found.append(name)
                continue
            if isinstance(spec, dict):
                fmt = (spec.get("format") or "").lower()
                if fmt in {"uri", "url"}:
                    found.append(name)
                    continue
                desc = spec.get("description") or ""
                if URL_PARAM_HINTS.search(desc):
                    found.append(name)
    return found


async def check_multi_request_pattern(
    _client: MCPClient,
    _config: ScanConfig,
    context: dict[str, Any],
) -> CheckResult:
    t0 = time.monotonic()
    tools = context.get("tools_full") or []
    if not tools:
        return CheckResult(
            name="multi-request-pattern",
            status=CheckStatus.SKIPPED_NOT_APPLICABLE,
            duration_ms=int((time.monotonic() - t0) * 1000),
            notes=["no tools advertised; nothing to analyze"],
        )

    flagged: list[dict[str, Any]] = []
    for t in tools:
        url_params = _scan_schema_for_url_params(t.get("inputSchema"))
        if url_params:
            flagged.append({
                "name": t.get("name"),
                "url_parameters": url_params,
                "description": (t.get("description") or "")[:200],
            })

    observations: list[Observation] = []
    if flagged:
        observations.append(
            Observation(
                title="tools with URL-shaped input parameters",
                severity=Severity.LOW,
                summary=(
                    "One or more advertised tools accept URL-like parameters. "
                    "If the server performs more than one outbound request per "
                    "invocation (for example a pre-fetch robots.txt check "
                    "followed by the main fetch), each request resolves DNS "
                    "independently by default. A DNS-rebinding attacker can "
                    "split the two lookups across different IPs."
                ),
                evidence={"tools": flagged},
                follow_up=(
                    "Time-box the tool invocation and inspect server-side DNS "
                    "behavior (tcpdump / Wireshark / strace) to confirm how "
                    "many outbound resolutions happen per call. If N > 1, "
                    "review mitigations: IP pinning across requests, single "
                    "httpx.AsyncClient reuse, explicit private-IP blocklist."
                ),
                see_also=[
                    "https://github.com/modelcontextprotocol/servers/security/advisories",
                    "https://www.jashidsany.com/security-research/ai-security/",
                ],
            )
        )

    return CheckResult(
        name="multi-request-pattern",
        status=CheckStatus.RAN,
        duration_ms=int((time.monotonic() - t0) * 1000),
        data={"tools_inspected": len(tools), "flagged": flagged},
        observations=observations,
    )
