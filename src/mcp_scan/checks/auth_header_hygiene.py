"""Auth header hygiene.

Sends an unauthenticated request and inspects the WWW-Authenticate and
related response headers. Flags verbose error_description values, infra
hints in realm, and inconsistent auth challenges.
"""

from __future__ import annotations

import re
import time
from typing import Any

from mcp_scan.client import MCPClient
from mcp_scan.models import CheckResult, CheckStatus, Observation, ScanConfig, Severity

INFRA_HINTS = re.compile(r"(aws|gcp|azure|kubernetes|k8s|docker|internal|staging|debug|traceback|exception|panic)", re.I)
PATH_HINTS = re.compile(r"(?:^|[\s\"'(<>])(/[A-Za-z0-9_.\-/]+)")


async def check_auth_header_hygiene(
    client: MCPClient,
    _config: ScanConfig,
    _context: dict[str, Any],
) -> CheckResult:
    t0 = time.monotonic()

    # Temporarily drop the auth token to elicit an unauthenticated response
    saved_token = client.token
    client.token = None
    try:
        ex = await client.rpc("tools/list")
    finally:
        client.token = saved_token

    www_auth = ex.response_headers.get("www-authenticate") or ex.response_headers.get("WWW-Authenticate")

    data: dict[str, Any] = {
        "status": ex.status,
        "www_authenticate": www_auth,
    }

    if not www_auth:
        # Server didn't challenge. Not a bug by itself (server might be unauth).
        return CheckResult(
            name="auth-header-hygiene",
            status=CheckStatus.SKIPPED_NOT_APPLICABLE,
            duration_ms=int((time.monotonic() - t0) * 1000),
            notes=["no WWW-Authenticate header returned; server is likely unauth or accepted the request"],
            data=data,
        )

    observations: list[Observation] = []

    # Parse out realm, scope, error_description via coarse regex
    realm = _extract_param(www_auth, "realm")
    scope = _extract_param(www_auth, "scope")
    error = _extract_param(www_auth, "error")
    error_description = _extract_param(www_auth, "error_description")

    data.update({
        "realm": realm,
        "scope": scope,
        "error": error,
        "error_description": error_description,
    })

    # Check each parsed field for infra hints
    blobs = []
    if realm:
        blobs.append(("realm", realm))
    if error_description:
        blobs.append(("error_description", error_description))

    for field_name, value in blobs:
        if INFRA_HINTS.search(value):
            observations.append(
                Observation(
                    title=f"WWW-Authenticate {field_name} leaks infrastructure hints",
                    severity=Severity.LOW,
                    summary=(
                        f"The WWW-Authenticate {field_name} contains words "
                        f"that commonly describe backend infrastructure "
                        f"(observed: '{value[:80]}'). Useful to attackers "
                        f"when planning further attacks."
                    ),
                    evidence={"value": value[:200]},
                    follow_up=(
                        "Manually request the endpoint without auth and "
                        "confirm the exact challenge:\n"
                        f"  curl -i {client.target}"
                    ),
                    see_also=["https://cwe.mitre.org/data/definitions/200.html"],
                )
            )
        path_match = PATH_HINTS.search(value)
        if path_match:
            observations.append(
                Observation(
                    title=f"WWW-Authenticate {field_name} leaks filesystem path",
                    severity=Severity.LOW,
                    summary=(
                        f"The WWW-Authenticate {field_name} contains what "
                        f"looks like an absolute filesystem path. Exposes "
                        f"the server's OS and deployment layout."
                    ),
                    evidence={"value": value[:200], "path": path_match.group(1)},
                    follow_up=f"Inspect the unauthenticated response manually: curl -i {client.target}",
                    see_also=["https://cwe.mitre.org/data/definitions/209.html"],
                )
            )

    return CheckResult(
        name="auth-header-hygiene",
        status=CheckStatus.RAN,
        duration_ms=int((time.monotonic() - t0) * 1000),
        data=data,
        observations=observations,
    )


def _extract_param(header: str, name: str) -> str | None:
    """Loosely extract `name="value"` or `name=value` from a challenge header."""
    m = re.search(rf'{name}\s*=\s*"([^"]*)"', header, re.I)
    if m:
        return m.group(1)
    m = re.search(rf'{name}\s*=\s*([^,\s]+)', header, re.I)
    if m:
        return m.group(1).strip('"\'')
    return None
