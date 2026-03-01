"""EU AI Act Compliance Scanner — tool-agnostic compliance checker for Python AI projects."""

__version__ = "1.0.0"

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
