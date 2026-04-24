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

# Narrow set of tokens that, when they appear as a parameter *name* or the
# JSON-schema *format*, strongly imply a URL-valued argument. Keywords like
# "source", "target", or "fetch" are too broad (trigger on timezone names,
# file paths, etc.) and are intentionally excluded.
URL_NAME_HINTS = re.compile(r"(?i)^(url|uri|link|endpoint|webhook|callback|href|address)s?$|url$|uri$")
URL_FORMATS = {"uri", "url", "uri-reference", "uri-template", "iri"}


def _scan_schema_for_url_params(schema: dict[str, Any] | None) -> list[str]:
    """Return the names of properties that look like URL-typed arguments.

    The check is conservative: we only flag parameters whose name matches a
    URL-like token, or whose JSON-schema `format` is a URL format. We do
    *not* scan descriptions because human prose frequently mentions
    "source"/"target"/"fetch" without implying a URL.
    """
    if not isinstance(schema, dict):
        return []
    found: list[str] = []
    props = schema.get("properties") or {}
    if isinstance(props, dict):
        for name, spec in props.items():
            if name and URL_NAME_HINTS.search(name):
                found.append(name)
                continue
            if isinstance(spec, dict):
                fmt = (spec.get("format") or "").lower()
                if fmt in URL_FORMATS:
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
