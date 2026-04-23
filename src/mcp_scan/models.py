"""Shared dataclasses for scan results, findings, and raw artifacts."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class CheckStatus(str, Enum):
    RAN = "ran"
    SKIPPED_MISSING_INPUT = "skipped-missing-input"
    SKIPPED_NOT_APPLICABLE = "skipped-not-applicable"
    ERRORED = "errored"


@dataclass
class Observation:
    """A single flagged observation from a check.

    An observation is not a vulnerability claim. It is a pattern the scanner
    noticed that matches a class of behavior associated with publicly disclosed
    bugs. The operator reviews in context.
    """

    title: str
    severity: Severity
    summary: str
    evidence: dict[str, Any] = field(default_factory=dict)
    follow_up: str | None = None
    see_also: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "title": self.title,
            "severity": self.severity.value,
            "summary": self.summary,
            "evidence": self.evidence,
            "follow_up": self.follow_up,
            "see_also": self.see_also,
        }


@dataclass
class CheckResult:
    """The outcome of running one check against a target."""

    name: str
    status: CheckStatus
    duration_ms: int
    notes: list[str] = field(default_factory=list)
    data: dict[str, Any] = field(default_factory=dict)
    observations: list[Observation] = field(default_factory=list)
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "status": self.status.value,
            "duration_ms": self.duration_ms,
            "notes": self.notes,
            "data": self.data,
            "observations": [o.to_dict() for o in self.observations],
            "error": self.error,
        }


@dataclass
class ScanConfig:
    target: str
    timeout_s: float = 30.0
    inter_request_delay_ms: int = 100
    proxy: str | None = None
    token: str | None = None
    include_secrets: bool = False
    user_agent: str = "mcp-scan/0.1.0 (+https://github.com/jashidsany/mcp-scan)"

    def redacted(self) -> dict[str, Any]:
        d = asdict(self)
        if not self.include_secrets and d.get("token"):
            d["token"] = "[REDACTED]"  # noqa: S105 - literal marker, not a credential
        return d


@dataclass
class ScanReport:
    target: str
    schema_version: str
    tool_version: str
    started_at: str
    finished_at: str
    duration_ms: int
    config: dict[str, Any]
    checks: list[CheckResult] = field(default_factory=list)

    @property
    def observations(self) -> list[Observation]:
        out: list[Observation] = []
        for c in self.checks:
            out.extend(c.observations)
        return out

    @property
    def exit_code(self) -> int:
        if any(c.status == CheckStatus.ERRORED for c in self.checks) and not self.observations:
            return 2
        if self.observations:
            return 1
        return 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "tool_version": self.tool_version,
            "target": self.target,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "duration_ms": self.duration_ms,
            "config": self.config,
            "checks": [c.to_dict() for c in self.checks],
        }
