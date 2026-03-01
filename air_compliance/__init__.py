"""AIR Compliance Checker — EU AI Act compliance scanner for AI agent projects."""

__version__ = "0.2.0"

from air_compliance.models import ComplianceReport, ArticleResult, CheckResult, Status
from air_compliance.scanner import ProjectScanner
from air_compliance.cli import main

__all__ = [
    "ProjectScanner",
    "ComplianceReport",
    "ArticleResult",
    "CheckResult",
    "Status",
    "main",
]