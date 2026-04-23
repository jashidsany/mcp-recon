# mcp-recon

Reconnaissance and known-issue scanner for Model Context Protocol (MCP) servers. Think of it as `nmap` for MCP: it fingerprints what's there and flags behavior patterns associated with publicly disclosed vulnerability classes. It does not declare a server "safe" or "unsafe" - it reports observations, and the operator interprets them in context.

## Use with authorization only

Only run `mcp-recon` against servers you own or have explicit permission to test. Unauthorized scanning may violate computer misuse laws in your jurisdiction. The tool is rate-limited by default and refuses to send state-mutating calls, but responsibility for scope is on the operator.

## Install

```bash
pipx install mcp-recon
# or
pip install --user mcp-recon
```

Python 3.10+ required.

## Quick start

```bash
# Human-readable scan of an MCP endpoint
mcp-recon scan https://example.com/api/mcp

# JSON output for automation
mcp-recon scan https://example.com/api/mcp --output json

# Markdown output for dropping into bug-bounty reports
mcp-recon scan https://example.com/api/mcp --output markdown

# Scope-binding probe on an OAuth-gated server
MCP_RECON_TOKEN=<access-token> mcp-recon scan https://example.com/api/mcp

# Route requests through Burp / mitmproxy
mcp-recon scan https://example.com/api/mcp --proxy http://127.0.0.1:8080
```

Exit codes:

| code | meaning |
|---|---|
| 0 | clean - all checks ran, no observations flagged |
| 1 | one or more observations flagged for review |
| 2 | scan error (target unreachable, misuse) |
| 3 | invalid arguments |

## What it checks

Ten checks, all generic. Each describes what it observed rather than declaring a verdict.

| check | what it looks for | class of bug it relates to |
|---|---|---|
| `fingerprint` | MCP protocol, tool / resource / prompt enumeration | baseline recon |
| `transport-hygiene` | HTTP (non-TLS) serving, unexpected success on GET/OPTIONS, `Server:` header surface | transport confidentiality (CWE-319), routing misconfig |
| `cors-policy` | Wildcard-with-credentials, echoed-Origin-with-credentials, `null` origin allowance | browser-based cross-origin abuse (CWE-942) |
| `auth-header-hygiene` | Infra hints, filesystem paths, and stack traces inside `WWW-Authenticate` challenges | information disclosure in auth errors (CWE-209) |
| `discovery-consistency` | Inconsistent `scopes_supported` / `grant_types_supported` across well-known documents | scope enforcement bypass (Zomato-class) |
| `error-verbosity` | Stack traces, filesystem paths, secret-shaped tokens in error responses | information disclosure (CWE-209, CWE-200) |
| `tool-description-anomalies` | Unicode control characters, zero-width, bidi override, length outliers in both tool names and descriptions | permission-prompt misrepresentation (Claude Code trust model lineage) |
| `multi-request-pattern` | Tools whose inputs accept URLs; flags N > 1 outbound request risk | DNS rebinding TOCTOU (mcp-server-fetch-class) |
| `undocumented-capabilities` | MCP methods responding with results outside advertised capabilities | debug endpoint exposure |
| `scope-binding` | Can a token with one scope call tools documented as requiring another? Requires `--token`. | authorization bypass (CWE-863, CWE-285) |

Each flagged observation ships with:
- A plain-English summary of what was observed.
- The concrete evidence the tool captured.
- A suggested manual follow-up command.
- Links to public CVEs or writeups that exemplify the class.

## Artifacts

Every scan writes a directory of raw JSON artifacts to `./mcp-recon-artifacts/<target>_<timestamp>/`:

```
report.json        structured result (schema-versioned)
exchanges.json     every HTTP request / response pair, with Authorization / Cookie headers redacted
```

Artifact directory is `chmod 700`. Individual files are `chmod 600`. Secrets are redacted by default; pass `--include-secrets` to disable redaction (use only when you need raw evidence for a report and understand the risk).

## Honest limits

- A clean scan does not mean a server is secure. The tool checks a finite set of known-issue patterns.
- Observations are not vulnerabilities. They're signals that match classes of previously disclosed bugs. Always validate manually before reporting.
- The tool is read-only at the MCP protocol layer. It never calls state-changing tools like `update_cart` or equivalents.
- Rate limiting is on by default (100ms between requests). Use `--aggressive` only against infrastructure you own.

## License

MIT. See `LICENSE`.

## Author

Jashid Sany - [jashidsany.com](https://www.jashidsany.com/) - [@jashidsany on GitHub](https://github.com/jashidsany)

Related research:

- [Zomato MCP OAuth scope not enforced](https://www.jashidsany.com/security-research/ai-security/zomato-mcp-oauth-scope-not-enforced/)
- [mcp-server-fetch DNS rebinding (GHSA in flight)](https://github.com/modelcontextprotocol/servers/security/advisories)
- Claude Code MCP trust-model findings at `jashidsany.com/security-research/ai-security/`
