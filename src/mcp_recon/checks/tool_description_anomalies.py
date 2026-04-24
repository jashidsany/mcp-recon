"""Tool description anomalies.

Scans advertised tool descriptions for patterns that could make what the
user sees in a permission prompt differ from what the tool actually does.
Generalizes the UI-spoofing concern from Claude Code permission-prompt
research.
"""

from __future__ import annotations

import time
import unicodedata
from typing import Any

from mcp_recon.client import MCPClient
from mcp_recon.models import CheckResult, CheckStatus, Observation, ScanConfig, Severity

CONTROL_CATEGORIES = {"Cc", "Cf"}
ZERO_WIDTH_CODEPOINTS = {0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF}
BIDI_CODEPOINTS = {0x202A, 0x202B, 0x202C, 0x202D, 0x202E, 0x2066, 0x2067, 0x2068, 0x2069}
# Whitespace-adjacent control chars that are legitimate in descriptions.
BENIGN_CONTROL = {0x09, 0x0A, 0x0D}  # tab, LF, CR


def _inspect(text: str) -> dict[str, Any]:
    control = 0
    zero_width = 0
    bidi = 0
    for ch in text:
        cp = ord(ch)
        if cp in BENIGN_CONTROL:
            continue
        if cp in ZERO_WIDTH_CODEPOINTS:
            zero_width += 1
        elif cp in BIDI_CODEPOINTS:
            bidi += 1
        elif unicodedata.category(ch) in CONTROL_CATEGORIES:
            control += 1
    return {
        "length": len(text),
        "control_chars": control,
        "zero_width_chars": zero_width,
        "bidi_chars": bidi,
    }


async def check_tool_description_anomalies(
    _client: MCPClient,
    _config: ScanConfig,
    context: dict[str, Any],
) -> CheckResult:
    t0 = time.monotonic()
    tools = context.get("tools_full") or []
    if not tools:
        return CheckResult(
            name="tool-description-anomalies",
            status=CheckStatus.SKIPPED_NOT_APPLICABLE,
            duration_ms=int((time.monotonic() - t0) * 1000),
            notes=["no tools advertised by the server; nothing to inspect"],
        )

    per_tool: list[dict[str, Any]] = []
    observations: list[Observation] = []

    lengths: list[int] = []
    for t in tools:
        name = t.get("name") or "<unnamed>"
        desc = t.get("description") or ""
        info = _inspect(desc)
        info["name"] = name
        info["name_inspection"] = _inspect(name)
        per_tool.append(info)
        lengths.append(info["length"])

        # Tool NAME anomalies (shown in every permission prompt) - separate observation
        name_info = info["name_inspection"]
        name_flags = []
        if name_info["control_chars"] > 0:
            name_flags.append(f"{name_info['control_chars']} control char(s)")
        if name_info["zero_width_chars"] > 0:
            name_flags.append(f"{name_info['zero_width_chars']} zero-width char(s)")
        if name_info["bidi_chars"] > 0:
            name_flags.append(f"{name_info['bidi_chars']} bidi override char(s)")

        if name_flags:
            observations.append(
                Observation(
                    title=f"suspicious characters in tool name: {name!r}",
                    severity=Severity.MEDIUM,
                    summary=(
                        "Tool name contains characters that render invisibly or "
                        "alter text direction. Tool names are shown in permission "
                        "prompts and logs; a name crafted to visually match a "
                        "benign tool could impersonate one. This is a stronger "
                        "signal than the same pattern in a description."
                    ),
                    evidence={"flags": name_flags, "name_codepoints": [hex(ord(c)) for c in name]},
                    follow_up=(
                        "Inspect the raw tool name byte-by-byte. Compare its "
                        "rendered form to any benign tool the MCP client might "
                        "already have approved."
                    ),
                    see_also=[
                        "https://www.jashidsany.com/security-research/ai-security/",
                    ],
                )
            )

        # Tool DESCRIPTION anomalies
        flags = []
        if info["control_chars"] > 0:
            flags.append(f"{info['control_chars']} control char(s)")
        if info["zero_width_chars"] > 0:
            flags.append(f"{info['zero_width_chars']} zero-width char(s)")
        if info["bidi_chars"] > 0:
            flags.append(f"{info['bidi_chars']} bidi override char(s)")

        if flags:
            observations.append(
                Observation(
                    title=f"suspicious characters in tool description: {name}",
                    severity=Severity.LOW,
                    summary=(
                        "Tool description contains characters that render invisibly "
                        "or alter text direction. If the MCP host surfaces this "
                        "description in a permission prompt, the user may see "
                        "different text from what the tool actually is."
                    ),
                    evidence={"flags": flags, "description_length": info["length"]},
                    follow_up=(
                        f"Inspect the raw description of tool '{name}' byte-by-byte. "
                        "Compare it against what is rendered in the MCP client's "
                        "permission prompt."
                    ),
                    see_also=[
                        "https://www.jashidsany.com/security-research/ai-security/",
                    ],
                )
            )

    # Length outlier detection (descriptions > 5x median)
    if lengths:
        sorted_lengths = sorted(lengths)
        median = sorted_lengths[len(sorted_lengths) // 2]
        if median > 0:
            for info in per_tool:
                if info["length"] > median * 5 and info["length"] > 500:
                    observations.append(
                        Observation(
                            title=f"tool description length outlier: {info['name']}",
                            severity=Severity.INFO,
                            summary=(
                                "One tool has a description significantly longer "
                                "than the others on this server. Long descriptions "
                                "can hide instruction-shaped text that MCP hosts "
                                "may treat as context for the LLM."
                            ),
                            evidence={
                                "this_length": info["length"],
                                "median_length": median,
                            },
                            follow_up=f"Read the full description of '{info['name']}' and look for anything that reads like an instruction to an LLM.",
                            see_also=[],
                        )
                    )

    return CheckResult(
        name="tool-description-anomalies",
        status=CheckStatus.RAN,
        duration_ms=int((time.monotonic() - t0) * 1000),
        data={"tools_inspected": len(tools), "per_tool": per_tool},
        observations=observations,
    )
