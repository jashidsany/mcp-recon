"""Scope-binding probe.

Requires an access token (--token or MCP_RECON_TOKEN). Given a token, the
check attempts to invoke each tool the server advertises, interpreting
the response codes to detect whether the token's scope actually constrains
which tools it can call.

Behavior:
  - If all tools return success: server does not appear to enforce scope
    at the application layer (Zomato-class pattern).
  - If all tools return 401/403/jsonrpc error: scope is enforced.
  - If mixed: tool invocation is normal; scope enforcement uncertain.

This is a dry probe: every call uses empty arguments. It relies on the
server responding with 401/403 for auth failures vs validation errors
for arg failures. That distinction is what produces signal.
"""

from __future__ import annotations

import time
from typing import Any

from mcp_recon.client import MCPClient
from mcp_recon.models import CheckResult, CheckStatus, Observation, ScanConfig, Severity


async def check_scope_binding(
    client: MCPClient,
    config: ScanConfig,
    context: dict[str, Any],
) -> CheckResult:
    t0 = time.monotonic()

    if not config.token:
        return CheckResult(
            name="scope-binding",
            status=CheckStatus.SKIPPED_MISSING_INPUT,
            duration_ms=int((time.monotonic() - t0) * 1000),
            notes=["no access token provided; run with --token <token> or MCP_RECON_TOKEN env var"],
        )

    tools = context.get("tools_full") or []
    if not tools:
        return CheckResult(
            name="scope-binding",
            status=CheckStatus.SKIPPED_NOT_APPLICABLE,
            duration_ms=int((time.monotonic() - t0) * 1000),
            notes=["no tools advertised; nothing to probe"],
        )

    per_tool: list[dict[str, Any]] = []
    auth_denied = 0
    arg_rejected = 0
    succeeded = 0

    for t in tools:
        name = t.get("name")
        if not name:
            continue
        try:
            ex = await client.rpc("tools/call", {"name": name, "arguments": {}})
        except Exception as e:  # noqa: BLE001
            per_tool.append({"name": name, "error": f"{type(e).__name__}: {e}"})
            continue

        classification = "unknown"
        rj = ex.response_json or {}
        if ex.status in (401, 403):
            classification = "auth-denied-http"
            auth_denied += 1
        elif "error" in rj:
            msg = ((rj["error"].get("message") or "") + " " + (rj["error"].get("data") or "")).lower() if isinstance(rj["error"], dict) else ""
            if any(kw in msg for kw in ("unauthorized", "forbidden", "invalid scope", "insufficient scope", "permission")):
                classification = "auth-denied-jsonrpc"
                auth_denied += 1
            else:
                classification = "arg-rejected"
                arg_rejected += 1
        elif "result" in rj:
            classification = "succeeded"
            succeeded += 1

        per_tool.append({
            "name": name,
            "status": ex.status,
            "classification": classification,
        })

    observations: list[Observation] = []

    total = auth_denied + arg_rejected + succeeded
    if total > 0 and succeeded == total:
        observations.append(
            Observation(
                title="all advertised tools callable with provided token",
                severity=Severity.MEDIUM,
                summary=(
                    "Every tool the server advertised was callable with the "
                    "provided token. If the token was issued with a scope "
                    "narrower than the full tool set, the server does not "
                    "appear to enforce scope at the application layer."
                ),
                evidence={"succeeded": succeeded, "total": total, "per_tool": per_tool},
                follow_up=(
                    "Confirm the token's issued scope claim (decode the JWT or "
                    "inspect the /token response). If the claim does not "
                    "include every tool called, you have a scope-enforcement "
                    "bypass."
                ),
                see_also=[
                    "https://www.jashidsany.com/security-research/ai-security/zomato-mcp-oauth-scope-not-enforced/",
                ],
            )
        )
    elif total > 0 and 0 < succeeded < total:
        # Normal case: some tools worked, some didn't. Informational.
        pass

    return CheckResult(
        name="scope-binding",
        status=CheckStatus.RAN,
        duration_ms=int((time.monotonic() - t0) * 1000),
        data={
            "tools_probed": len(per_tool),
            "succeeded": succeeded,
            "auth_denied": auth_denied,
            "arg_rejected": arg_rejected,
            "per_tool": per_tool,
        },
        observations=observations,
    )
