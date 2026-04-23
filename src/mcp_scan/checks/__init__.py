"""Check registry. Each check is an async callable returning CheckResult."""

from __future__ import annotations

from collections.abc import Awaitable, Callable

from mcp_scan.client import MCPClient
from mcp_scan.models import CheckResult, ScanConfig

from .auth_header_hygiene import check_auth_header_hygiene
from .cors_policy import check_cors_policy
from .discovery_consistency import check_discovery_consistency
from .error_verbosity import check_error_verbosity
from .fingerprint import check_fingerprint
from .multi_request_pattern import check_multi_request_pattern
from .scope_binding import check_scope_binding
from .tool_description_anomalies import check_tool_description_anomalies
from .transport_hygiene import check_transport_hygiene
from .undocumented_capabilities import check_undocumented_capabilities

CheckFn = Callable[[MCPClient, ScanConfig, dict], Awaitable[CheckResult]]

# Registry in execution order. Earlier checks produce data later ones may use
# (via the shared `context` dict passed by the runner).
REGISTRY: list[tuple[str, CheckFn]] = [
    ("fingerprint", check_fingerprint),
    ("transport-hygiene", check_transport_hygiene),
    ("cors-policy", check_cors_policy),
    ("auth-header-hygiene", check_auth_header_hygiene),
    ("discovery-consistency", check_discovery_consistency),
    ("error-verbosity", check_error_verbosity),
    ("tool-description-anomalies", check_tool_description_anomalies),
    ("multi-request-pattern", check_multi_request_pattern),
    ("undocumented-capabilities", check_undocumented_capabilities),
    ("scope-binding", check_scope_binding),
]

__all__ = [
    "REGISTRY",
    "CheckFn",
    "check_auth_header_hygiene",
    "check_cors_policy",
    "check_discovery_consistency",
    "check_error_verbosity",
    "check_fingerprint",
    "check_multi_request_pattern",
    "check_scope_binding",
    "check_tool_description_anomalies",
    "check_transport_hygiene",
    "check_undocumented_capabilities",
]
