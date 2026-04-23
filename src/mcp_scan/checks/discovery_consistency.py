"""Discovery document consistency.

Fetches standard .well-known OAuth/OIDC/MCP discovery documents and flags
when two of them disagree on load-bearing fields like `scopes_supported`.

Rationale: inconsistent discovery advertisement has preceded scope
enforcement bypass bugs (e.g. Zomato MCP OAuth scope not enforced).
"""

from __future__ import annotations

import time
from typing import Any
from urllib.parse import urlparse

from mcp_scan.client import MCPClient
from mcp_scan.models import CheckResult, CheckStatus, Observation, ScanConfig, Severity

WELL_KNOWN_PATHS = [
    "/.well-known/oauth-authorization-server",
    "/.well-known/openid-configuration",
    "/.well-known/oauth-protected-resource",
    "/.well-known/customer-account-api",
]


async def check_discovery_consistency(
    client: MCPClient,
    _config: ScanConfig,
    context: dict[str, Any],
) -> CheckResult:
    t0 = time.monotonic()

    parsed = urlparse(client.target)
    if not parsed.scheme or not parsed.netloc:
        return CheckResult(
            name="discovery-consistency",
            status=CheckStatus.ERRORED,
            duration_ms=int((time.monotonic() - t0) * 1000),
            error="target URL missing scheme or netloc",
        )

    origin = f"{parsed.scheme}://{parsed.netloc}"
    fetched: dict[str, dict[str, Any]] = {}

    for path in WELL_KNOWN_PATHS:
        url = origin + path
        try:
            ex = await client.get(url)
        except Exception as e:  # noqa: BLE001
            fetched[path] = {"status": None, "error": f"{type(e).__name__}: {e}"}
            continue
        fetched[path] = {
            "status": ex.status,
            "body": ex.response_json if ex.response_json else None,
        }

    available = {p: d for p, d in fetched.items() if d.get("status") == 200 and d.get("body")}

    data: dict[str, Any] = {
        "paths_tried": WELL_KNOWN_PATHS,
        "paths_found": list(available.keys()),
    }
    context["discovery_docs"] = available
    observations: list[Observation] = []

    if len(available) < 2:
        return CheckResult(
            name="discovery-consistency",
            status=CheckStatus.SKIPPED_NOT_APPLICABLE,
            duration_ms=int((time.monotonic() - t0) * 1000),
            notes=[f"only {len(available)} discovery document(s) found; at least 2 needed for consistency check"],
            data=data,
        )

    # Compare scopes_supported across the available docs
    scope_sets: dict[str, set[str]] = {}
    for path, d in available.items():
        body = d["body"] or {}
        s = body.get("scopes_supported")
        if isinstance(s, list):
            scope_sets[path] = set(s)

    data["scopes_supported_per_doc"] = {k: sorted(v) for k, v in scope_sets.items()}

    if len(scope_sets) >= 2:
        first_set = next(iter(scope_sets.values()))
        if any(s != first_set for s in scope_sets.values()):
            per_doc = "\n  ".join(
                f"{path}: {sorted(s)}" for path, s in scope_sets.items()
            )
            observations.append(
                Observation(
                    title="discovery documents disagree on scopes_supported",
                    severity=Severity.MEDIUM,
                    summary=(
                        "Two or more OAuth/OIDC discovery documents advertise "
                        "different sets of supported scopes. This is a smell: "
                        "it has preceded scope enforcement bypass bugs in "
                        "other MCP and OAuth deployments."
                    ),
                    evidence={"scopes_per_doc": {k: sorted(v) for k, v in scope_sets.items()}},
                    follow_up=(
                        "Manually compare the well-known documents:\n"
                        + "\n".join(f"  curl {origin}{p}" for p in available)
                        + "\n"
                        + per_doc
                    ),
                    see_also=[
                        "https://www.jashidsany.com/security-research/ai-security/zomato-mcp-oauth-scope-not-enforced/",
                    ],
                )
            )

    # Compare grant_types_supported across docs
    grant_sets: dict[str, set[str]] = {}
    for path, d in available.items():
        body = d["body"] or {}
        g = body.get("grant_types_supported")
        if isinstance(g, list):
            grant_sets[path] = set(g)

    if len(grant_sets) >= 2:
        first_set = next(iter(grant_sets.values()))
        if any(s != first_set for s in grant_sets.values()):
            observations.append(
                Observation(
                    title="discovery documents disagree on grant_types_supported",
                    severity=Severity.LOW,
                    summary=(
                        "OAuth discovery documents advertise different supported "
                        "grant types. Less severe than scope inconsistency but "
                        "worth manual review."
                    ),
                    evidence={"grants_per_doc": {k: sorted(v) for k, v in grant_sets.items()}},
                    follow_up="Compare grant_types_supported across all fetched discovery documents.",
                    see_also=[],
                )
            )

    return CheckResult(
        name="discovery-consistency",
        status=CheckStatus.RAN,
        duration_ms=int((time.monotonic() - t0) * 1000),
        data=data,
        observations=observations,
    )
