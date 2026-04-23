"""CORS policy probe.

Sends a request with an attacker-shaped Origin header. Inspects
Access-Control-Allow-* response headers. Flags wildcard-with-credentials,
echoed-Origin-with-credentials, and `null` allowance - browser-exposed
SSRF-from-origin primitives.
"""

from __future__ import annotations

import time
from typing import Any

from mcp_scan.client import MCPClient
from mcp_scan.models import CheckResult, CheckStatus, Observation, ScanConfig, Severity

ATTACKER_ORIGIN = "https://evil.example"


async def check_cors_policy(
    client: MCPClient,
    _config: ScanConfig,
    _context: dict[str, Any],
) -> CheckResult:
    t0 = time.monotonic()

    observations: list[Observation] = []
    data: dict[str, Any] = {}

    # Preflight OPTIONS with an attacker Origin
    headers = client._build_headers({
        "Origin": ATTACKER_ORIGIN,
        "Access-Control-Request-Method": "POST",
        "Access-Control-Request-Headers": "Content-Type, Authorization",
    })
    try:
        ex = await client._request("OPTIONS", client.target, headers)
    except Exception as e:  # noqa: BLE001
        return CheckResult(
            name="cors-policy",
            status=CheckStatus.ERRORED,
            duration_ms=int((time.monotonic() - t0) * 1000),
            error=f"{type(e).__name__}: {e}",
        )

    acao = ex.response_headers.get("access-control-allow-origin") or ex.response_headers.get("Access-Control-Allow-Origin")
    acac = ex.response_headers.get("access-control-allow-credentials") or ex.response_headers.get("Access-Control-Allow-Credentials")
    acam = ex.response_headers.get("access-control-allow-methods") or ex.response_headers.get("Access-Control-Allow-Methods")
    acah = ex.response_headers.get("access-control-allow-headers") or ex.response_headers.get("Access-Control-Allow-Headers")

    data["preflight_status"] = ex.status
    data["access_control_allow_origin"] = acao
    data["access_control_allow_credentials"] = acac
    data["access_control_allow_methods"] = acam
    data["access_control_allow_headers"] = acah

    credentials_allowed = (acac or "").strip().lower() == "true"

    # Case 1: wildcard ACAO with credentials true
    if acao == "*" and credentials_allowed:
        observations.append(
            Observation(
                title="CORS allows wildcard origin with credentials",
                severity=Severity.HIGH,
                summary=(
                    "Access-Control-Allow-Origin is '*' and "
                    "Access-Control-Allow-Credentials is true. Browsers reject "
                    "this combination in practice, but servers that send it "
                    "are often misconfigured elsewhere too. Treat as a strong "
                    "smell for broader CORS misconfiguration."
                ),
                evidence={
                    "access_control_allow_origin": acao,
                    "access_control_allow_credentials": acac,
                },
                follow_up=(
                    "Manually send:\n"
                    f"  curl -i -H 'Origin: {ATTACKER_ORIGIN}' -X OPTIONS {client.target}\n"
                    "Review whether browsers could reach this endpoint from "
                    "an attacker-controlled origin with cookies/auth attached."
                ),
                see_also=["https://cwe.mitre.org/data/definitions/942.html"],
            )
        )

    # Case 2: echoed origin with credentials
    if acao == ATTACKER_ORIGIN and credentials_allowed:
        observations.append(
            Observation(
                title="CORS echoes attacker Origin with credentials",
                severity=Severity.HIGH,
                summary=(
                    "The server reflected an attacker-supplied Origin into "
                    "Access-Control-Allow-Origin and set Allow-Credentials: "
                    "true. A browser under attacker control can issue "
                    "cross-origin requests with cookies and read responses."
                ),
                evidence={
                    "reflected_origin": acao,
                    "access_control_allow_credentials": acac,
                },
                follow_up=(
                    "Test with additional malicious origins: https://evil.example, "
                    "http://localhost:8080, null. If reflection is unconditional, "
                    "a browser-based attack is viable."
                ),
                see_also=["https://cwe.mitre.org/data/definitions/942.html"],
            )
        )

    # Case 3: `null` origin explicitly allowed
    if (acao or "").lower() == "null":
        observations.append(
            Observation(
                title="CORS allows 'null' origin",
                severity=Severity.MEDIUM,
                summary=(
                    "Access-Control-Allow-Origin is 'null'. Browsers assign "
                    "origin 'null' to sandboxed iframes, data: URLs, and "
                    "certain redirects. An attacker can host content whose "
                    "browser origin is 'null' and bypass origin restrictions."
                ),
                evidence={"access_control_allow_origin": acao},
                follow_up=(
                    "Host a sandboxed <iframe src='data:text/html,...'> that "
                    "fetches this endpoint. If it reads the response, origin "
                    "protection is effectively disabled."
                ),
                see_also=["https://w3c.github.io/webappsec-cors-for-developers/"],
            )
        )

    return CheckResult(
        name="cors-policy",
        status=CheckStatus.RAN,
        duration_ms=int((time.monotonic() - t0) * 1000),
        data=data,
        observations=observations,
    )
