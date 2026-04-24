# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-04-24

### Added

- **Stdio transport support.** New `--stdio "command"` flag spawns the MCP
  server as a subprocess and speaks newline-delimited JSON-RPC over
  stdin / stdout. Enables scanning the reference servers in
  `modelcontextprotocol/servers` (fetch, git, time, memory, filesystem,
  sequentialthinking, everything) and any other stdio-first MCP server.
- Transport abstraction (`mcp_recon.transport`) with `HttpTransport` and
  `StdioTransport` implementations. `MCPClient` now delegates to a
  transport instead of hard-coding HTTP.
- `CheckStatus.SKIPPED_NOT_APPLICABLE` is used to mark HTTP-only checks
  when running against a stdio target, instead of erroring.
- `server_stderr.txt` artifact for stdio scans: captures the server's
  stderr tail, useful for triaging startup banners and warnings.

### Changed

- **False-positive tuning** after running against every reference server
  in `modelcontextprotocol/servers`:
  - `tool-description-anomalies` no longer counts `\n`, `\r`, `\t` as
    suspicious control characters; they're normal in multi-line
    descriptions.
  - `multi-request-pattern` tightened: matches only on parameter *name*
    (url, uri, link, endpoint, webhook, callback, href, address) or
    JSON-schema `format: uri/url`. Descriptive keywords like "source",
    "target", "fetch" removed - they triggered on timezone conversion
    and file-path arguments without implying a URL.
  - `undocumented-capabilities` no longer probes `ping` or
    `notifications/initialized`: `ping` is mandatory on every MCP server
    per spec, `notifications/initialized` is a one-way notification.
- `CheckStatus` docstrings clarified. No API breakage.
- Schema version bumped to `1.1` to reflect the new `transport` field
  in exchange records.

### Notes

- Validated against the seven reference servers in the
  `modelcontextprotocol/servers` repo. One observation on
  `mcp-server-fetch` matches the already-disclosed DNS rebinding bug
  (GHSA filed). Other reference servers produced clean scans.

## [0.1.0] - 2026-04-22

Initial public release. Ten HTTP checks, human / JSON / markdown output,
artifact capture with header redaction, rate limiting by default,
trusted-publishing release pipeline.
