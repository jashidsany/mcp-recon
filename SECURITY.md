# Security policy

## Reporting a vulnerability in `mcp-recon`

If you discover a vulnerability in `mcp-recon` itself (the scanner, not a target you've scanned with it), report it privately.

- Preferred: [GitHub Security Advisory](https://github.com/jashidsany/mcp-recon/security/advisories/new)
- Backup: email `jashid.sany@gmail.com` with subject line starting `[mcp-recon security]`

Please include:
- `mcp-recon` version (`mcp-recon --version`)
- Python version
- Steps to reproduce
- Expected vs actual behavior
- Impact, if known

## Threat model

`mcp-recon` is a scanning tool. It makes outbound HTTP requests to user-provided MCP endpoints. The intended trust boundaries:

1. **The user** is trusted. They choose what to scan.
2. **The target MCP server** is not trusted. Its responses are attacker-controlled from the tool's perspective.
3. **The artifacts directory** is trusted (and created `chmod 700`).

### What `mcp-recon` protects against

- Accidentally logging OAuth tokens or session cookies to artifacts (redacted by default).
- Sending state-changing calls to the target (the tool does not invoke mutation tools like `update_cart`; it only calls read-only and enumeration methods, plus `tools/call` with empty arguments during the scope-binding probe, which is defensive: empty args generally yield validation errors, not mutations).
- Producing output that could be misread as a security certification ("safe / unsafe"). The tool uses "observation" language and explicit references to public CVEs.

### What `mcp-recon` does NOT protect against

- A malicious or compromised target server sending response bodies that, when rendered, exploit a terminal emulator, shell, or text viewer.
- A malicious target triggering resource exhaustion via extremely large responses. The tool reads response bodies without streaming limits beyond `httpx` defaults.
- Runtime in environments where `./mcp-recon-artifacts` is not a safe location (e.g., world-writable directories).

### Dependencies

`mcp-recon` pins major versions of its direct dependencies (`httpx`, `typer`, `rich`). Transitive dependencies are resolved by pip / `uv` at install time. Keeping them current is the operator's responsibility.

## Supported versions

| Version | Status |
|---|---|
| 0.1.x | Active |

Earlier versions are not maintained.
