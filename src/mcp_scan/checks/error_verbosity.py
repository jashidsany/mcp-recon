"""Error verbosity: send malformed inputs, flag stack traces and path leaks."""

from __future__ import annotations

import re
import time
from typing import Any

from mcp_scan.client import MCPClient
from mcp_scan.models import CheckResult, CheckStatus, Observation, ScanConfig, Severity

STACK_TRACE_MARKERS = [
    "Traceback (most recent call last)",
    "at java.",
    "\tat ",
    "System.Exception",
    "panic: ",
    "goroutine ",
    "File \"/",
    "  File \"",
]

PATH_LEAK_PATTERNS = [
    re.compile(r"(?:^|[\s\"'(<>])(/home/[A-Za-z0-9_.\-/]+)", re.I),
    re.compile(r"(?:^|[\s\"'(<>])(/Users/[A-Za-z0-9_.\-/]+)", re.I),
    re.compile(r"(?:^|[\s\"'(<>])([A-Z]:\\\\[A-Za-z0-9_.\-\\\\]+)", re.I),
    re.compile(r"(?:^|[\s\"'(<>])(/var/[A-Za-z0-9_.\-/]+)", re.I),
    re.compile(r"(?:^|[\s\"'(<>])(/opt/[A-Za-z0-9_.\-/]+)", re.I),
    re.compile(r"(?:^|[\s\"'(<>])(/srv/[A-Za-z0-9_.\-/]+)", re.I),
    re.compile(r"(?:^|[\s\"'(<>])(/root/[A-Za-z0-9_.\-/]+)", re.I),
]

SECRET_LIKE = [
    re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),  # AWS access key
    re.compile(r"\bghp_[A-Za-z0-9]{36,}\b"),  # GitHub PAT
    re.compile(r"\bsk-[A-Za-z0-9]{32,}\b"),  # OpenAI-ish
]


async def check_error_verbosity(
    client: MCPClient,
    _config: ScanConfig,
    _context: dict[str, Any],
) -> CheckResult:
    t0 = time.monotonic()

    # Batch of intentionally malformed / edge-case requests.
    probes: list[tuple[str, dict[str, Any] | None, str | None]] = [
        ("bad-method-name", {}, "totally-not-a-method"),
        ("tools-call-missing-args", {"name": "does_not_exist_xyz"}, "tools/call"),
        ("tools-call-null-args", {"name": "does_not_exist_xyz", "arguments": None}, "tools/call"),
        ("tools-call-huge-payload", {"name": "does_not_exist_xyz", "arguments": {"x": "A" * 16384}}, "tools/call"),
    ]

    responses: list[dict[str, Any]] = []
    for label, params, method in probes:
        try:
            ex = await client.rpc(method or label, params)
            body = ex.response_body_preview
            responses.append({
                "label": label,
                "status": ex.status,
                "body_preview": body[:1000],
            })
        except Exception as e:  # noqa: BLE001
            responses.append({"label": label, "error": f"{type(e).__name__}: {e}"})

    observations: list[Observation] = []

    # Aggregate scan
    combined = " ".join((r.get("body_preview") or "") for r in responses)

    trace_hits = [m for m in STACK_TRACE_MARKERS if m in combined]
    if trace_hits:
        observations.append(
            Observation(
                title="stack trace exposed in error response",
                severity=Severity.LOW,
                summary="Malformed request provoked a server response that contained stack-trace-style text. Server internals may be exposed to unauthenticated callers.",
                evidence={"markers_found": trace_hits[:5]},
                follow_up="Review each probe's body_preview in the saved artifacts to confirm the trace and identify what's leaking.",
                see_also=["https://cwe.mitre.org/data/definitions/209.html"],
            )
        )

    path_hits: list[str] = []
    for pat in PATH_LEAK_PATTERNS:
        path_hits.extend(pat.findall(combined)[:3])
    if path_hits:
        observations.append(
            Observation(
                title="filesystem paths leaked in error response",
                severity=Severity.LOW,
                summary="Error responses included absolute filesystem paths. Exposes server OS, deployment layout, or app structure.",
                evidence={"paths_observed": path_hits[:5]},
                follow_up="Review the probe that triggered the leak in artifacts and report to the vendor.",
                see_also=["https://cwe.mitre.org/data/definitions/209.html"],
            )
        )

    secret_hits: list[str] = []
    for pat in SECRET_LIKE:
        for m in pat.findall(combined):
            secret_hits.append(m[:8] + "…")
    if secret_hits:
        observations.append(
            Observation(
                title="secret-shaped token in error response",
                severity=Severity.HIGH,
                summary="Response body contained a substring that matches common secret formats (AWS key, GitHub PAT, etc.). Investigate before reporting.",
                evidence={"matches_truncated": secret_hits[:3]},
                follow_up="Run the scan again with --include-secrets and inspect the raw artifact. Confirm the match is a real secret, not a documentation example, before submission.",
                see_also=["https://cwe.mitre.org/data/definitions/200.html"],
            )
        )

    return CheckResult(
        name="error-verbosity",
        status=CheckStatus.RAN,
        duration_ms=int((time.monotonic() - t0) * 1000),
        data={"probes_sent": len(probes), "responses": responses},
        observations=observations,
    )
