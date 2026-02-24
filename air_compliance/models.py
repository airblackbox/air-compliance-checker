"""Data models for compliance check results."""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Optional


class Status(enum.Enum):
    """Status of a compliance check."""
    PASS = "pass"
    FAIL = "fail"
    WARN = "warn"
    SKIP = "skip"


@dataclass
class CheckResult:
    """Result of a single compliance check."""
    name: str
    status: Status
    description: str
    requirement: str
    recommendation: Optional[str] = None
    evidence: Optional[str] = None


@dataclass
class ArticleResult:
    """Compliance results for a single EU AI Act article."""
    article: str
    title: str
    checks: list[CheckResult] = field(default_factory=list)

    @property
    def status(self) -> Status:
        """Overall status: FAIL if any check fails, WARN if any warns, else PASS."""
        statuses = [c.status for c in self.checks]
        if Status.FAIL in statuses:
            return Status.FAIL
        if Status.WARN in statuses:
            return Status.WARN
        if all(s == Status.SKIP for s in statuses):
            return Status.SKIP
        return Status.PASS

    @property
    def pass_count(self) -> int:
        return sum(1 for c in self.checks if c.status == Status.PASS)

    @property
    def fail_count(self) -> int:
        return sum(1 for c in self.checks if c.status == Status.FAIL)

    @property
    def warn_count(self) -> int:
        return sum(1 for c in self.checks if c.status == Status.WARN)


@dataclass
class ComplianceReport:
    """Full EU AI Act compliance report for a project."""
    project_path: str
    articles: list[ArticleResult] = field(default_factory=list)
    frameworks_detected: list[str] = field(default_factory=list)
    scan_errors: list[str] = field(default_factory=list)

    @property
    def overall_status(self) -> Status:
        statuses = [a.status for a in self.articles]
        if Status.FAIL in statuses:
            return Status.FAIL
        if Status.WARN in statuses:
            return Status.WARN
        return Status.PASS

    @property
    def total_checks(self) -> int:
        return sum(len(a.checks) for a in self.articles)

    @property
    def total_pass(self) -> int:
        return sum(a.pass_count for a in self.articles)

    @property
    def total_fail(self) -> int:
        return sum(a.fail_count for a in self.articles)

    @property
    def total_warn(self) -> int:
        return sum(a.warn_count for a in self.articles)

    @property
    def coverage_pct(self) -> float:
        """Percentage of checks that pass or warn (vs fail)."""
        total = self.total_checks
        if total == 0:
            return 0.0
        return ((self.total_pass + self.total_warn) / total) * 100