"""Fingerprint: MCP protocol initialize + tool/resource/prompt enumeration."""

from __future__ import annotations

import time
from typing import Any

from mcp_scan.client import MCPClient
from mcp_scan.models import CheckResult, CheckStatus, ScanConfig


async def check_fingerprint(
    client: MCPClient,
    _config: ScanConfig,
    context: dict[str, Any],
) -> CheckResult:
    t0 = time.monotonic()
    data: dict[str, Any] = {}
    notes: list[str] = []

    try:
        init = await client.initialize()
        data["initialize_status"] = init.status
        if init.response_json and "result" in init.response_json:
            res = init.response_json["result"]
            data["protocol_version"] = res.get("protocolVersion")
            data["server_info"] = res.get("serverInfo")
            data["capabilities"] = list((res.get("capabilities") or {}).keys())
        elif init.response_json and "error" in init.response_json:
            notes.append(f"initialize returned error: {init.response_json['error'].get('message','')}")
        elif init.error:
            return CheckResult(
                name="fingerprint",
                status=CheckStatus.ERRORED,
                duration_ms=int((time.monotonic() - t0) * 1000),
                error=init.error,
            )

        tl = await client.tools_list()
        tools: list[dict[str, Any]] = []
        if tl.response_json and "result" in tl.response_json:
            tools = tl.response_json["result"].get("tools") or []
        data["tools"] = [
            {
                "name": t.get("name"),
                "description_length": len(t.get("description") or ""),
                "has_input_schema": "inputSchema" in t,
            }
            for t in tools
        ]
        # Store full tool records in context for downstream checks.
        context["tools_full"] = tools
        context["tool_names"] = [t.get("name") for t in tools]

        rl = await client.resources_list()
        resources = []
        if rl.response_json and "result" in rl.response_json:
            resources = rl.response_json["result"].get("resources") or []
        data["resources_count"] = len(resources)
        context["resources"] = resources

        pl = await client.prompts_list()
        prompts = []
        if pl.response_json and "result" in pl.response_json:
            prompts = pl.response_json["result"].get("prompts") or []
        data["prompts_count"] = len(prompts)
        context["prompts"] = prompts

    except Exception as e:  # noqa: BLE001 - surface as ERRORED
        return CheckResult(
            name="fingerprint",
            status=CheckStatus.ERRORED,
            duration_ms=int((time.monotonic() - t0) * 1000),
            error=f"{type(e).__name__}: {e}",
        )

    return CheckResult(
        name="fingerprint",
        status=CheckStatus.RAN,
        duration_ms=int((time.monotonic() - t0) * 1000),
        notes=notes,
        data=data,
    )
