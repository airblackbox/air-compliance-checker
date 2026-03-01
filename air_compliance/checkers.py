"""Article-specific compliance checkers for EU AI Act (tool-agnostic)."""

from __future__ import annotations

from air_compliance.models import ArticleResult, CheckResult, Status
from air_compliance.scanner import ScanResult


def check_article_9(scan: ScanResult) -> ArticleResult:
    """Article 9 — Risk Management System."""
    art = ArticleResult(article="Article 9", title="Risk Management System")

    # Check 1: Risk classification exists
    art.checks.append(CheckResult(
        name="risk_classification",
        status=Status.PASS if scan.has_risk_classification else Status.FAIL,
        description="Risk levels defined for AI operations",
        requirement="Identify and analyse known and foreseeable risks (Art. 9(2)(a))",
        recommendation=None if scan.has_risk_classification else
            "Add risk classification to your AI operations (e.g., severity levels, risk scores, threat categories)",
        evidence=_evidence(scan, "has_risk_classification"),
    ))

    # Check 2: Access control / permission checks
    art.checks.append(CheckResult(
        name="access_control",
        status=Status.PASS if scan.has_access_control else Status.WARN,
        description="Access control on AI-driven actions",
        requirement="Adopt suitable risk management measures (Art. 9(2)(b))",
        recommendation=None if scan.has_access_control else
            "Add permission checks or auth decorators to restrict which actions the AI can take",
        evidence=_evidence(scan, "has_access_control"),
    ))

    # Check 3: Risk decisions logged
    art.checks.append(CheckResult(
        name="risk_audit",
        status=Status.PASS if scan.has_risk_audit else Status.WARN,
        description="Risk decisions logged for review",
        requirement="Demonstrate residual risk is acceptable (Art. 9(4))",
        recommendation=None if scan.has_risk_audit else
            "Log risk classification and blocking decisions (e.g., using structlog, Python logging, or any audit system)",
        evidence=_evidence(scan, "has_risk_audit"),
    ))

    return art


def check_article_10(scan: ScanResult) -> ArticleResult:
    """Article 10 — Data and Data Governance."""
    art = ArticleResult(article="Article 10", title="Data and Data Governance")

    # Check 1: Input validation
    art.checks.append(CheckResult(
        name="input_validation",
        status=Status.PASS if scan.has_input_validation else Status.FAIL,
        description="Input data validated with schemas or type checking",
        requirement="Data governance and management practices (Art. 10(2))",
        recommendation=None if scan.has_input_validation else
            "Add input validation (e.g., Pydantic BaseModel, marshmallow Schema, jsonschema, or dataclasses)",
        evidence=_evidence(scan, "has_input_validation"),
    ))

    # Check 2: PII / sensitive data handling
    art.checks.append(CheckResult(
        name="pii_handling",
        status=Status.PASS if scan.has_pii_handling else Status.WARN,
        description="Personal/sensitive data identified and handled",
        requirement="Appropriate data minimisation measures (Art. 10(2)(f))",
        recommendation=None if scan.has_pii_handling else
            "Add PII detection and handling (e.g., presidio, scrubadub, regex-based redaction, or manual masking)",
        evidence=_evidence(scan, "has_pii_handling"),
    ))

    # Check 3: Data schemas / typed models
    art.checks.append(CheckResult(
        name="data_schemas",
        status=Status.PASS if scan.has_data_schemas else Status.WARN,
        description="Data structures defined with typed schemas",
        requirement="Relevant data preparation processing operations (Art. 10(2)(d))",
        recommendation=None if scan.has_data_schemas else
            "Define typed data models (e.g., Pydantic, dataclasses, TypedDict, marshmallow)",
        evidence=_evidence(scan, "has_data_schemas"),
    ))

    # Check 4: Data provenance
    art.checks.append(CheckResult(
        name="data_provenance",
        status=Status.PASS if scan.has_data_provenance else Status.WARN,
        description="Data sources tracked with provenance information",
        requirement="Information about data origin and collection (Art. 10(2)(b))",
        recommendation=None if scan.has_data_provenance else
            "Track data sources and lineage (e.g., source URLs, document IDs, content hashes)",
        evidence=_evidence(scan, "has_data_provenance"),
    ))

    return art


def check_article_11(scan: ScanResult) -> ArticleResult:
    """Article 11 — Technical Documentation."""
    art = ArticleResult(article="Article 11", title="Technical Documentation")

    # Check 1: Logging
    art.checks.append(CheckResult(
        name="logging",
        status=Status.PASS if scan.has_logging else Status.FAIL,
        description="Operations logged for traceability",
        requirement="General description of the AI system kept up to date (Art. 11(1))",
        recommendation=None if scan.has_logging else
            "Add logging (e.g., Python logging module, structlog, loguru)",
        evidence=_evidence(scan, "has_logging"),
    ))

    # Check 2: Code documentation
    art.checks.append(CheckResult(
        name="documentation",
        status=Status.PASS if scan.has_docstrings else Status.WARN,
        description="Code documented with docstrings or external docs",
        requirement="Detailed description of system elements (Art. 11(1)(b))",
        recommendation=None if scan.has_docstrings else
            "Add docstrings to functions and classes describing their purpose and behavior",
        evidence=_evidence(scan, "has_docstrings"),
    ))

    # Check 3: Type hints
    art.checks.append(CheckResult(
        name="type_hints",
        status=Status.PASS if scan.has_type_hints else Status.WARN,
        description="Functions annotated with type hints",
        requirement="Description of system architecture and data flows (Art. 11(1)(b))",
        recommendation=None if scan.has_type_hints else
            "Add type hints to function signatures for clearer documentation of data flows",
        evidence=_evidence(scan, "has_type_hints"),
    ))

    return art


def check_article_12(scan: ScanResult) -> ArticleResult:
    """Article 12 — Record-Keeping."""
    art = ArticleResult(article="Article 12", title="Record-Keeping")

    # Check 1: Structured logging
    art.checks.append(CheckResult(
        name="structured_logging",
        status=Status.PASS if scan.has_structured_logging else Status.WARN,
        description="Logs use structured format (JSON, key-value)",
        requirement="Automatic recording of events (logs) (Art. 12(1))",
        recommendation=None if scan.has_structured_logging else
            "Use structured logging for machine-readable logs (e.g., structlog, python-json-logger)",
        evidence=_evidence(scan, "has_structured_logging"),
    ))

    # Check 2: Audit trail
    art.checks.append(CheckResult(
        name="audit_trail",
        status=Status.PASS if scan.has_audit_trail else Status.FAIL,
        description="Audit trail captures key events and decisions",
        requirement="Traceability of the AI system functioning (Art. 12(2))",
        recommendation=None if scan.has_audit_trail else
            "Add audit logging for key AI decisions and actions (e.g., dedicated audit log, event store, database table)",
        evidence=_evidence(scan, "has_audit_trail"),
    ))

    # Check 3: Timestamps
    art.checks.append(CheckResult(
        name="timestamps",
        status=Status.PASS if scan.has_timestamps else Status.WARN,
        description="Events timestamped for chronological ordering",
        requirement="Logs must enable monitoring of operation (Art. 12(1))",
        recommendation=None if scan.has_timestamps else
            "Add timestamps to log entries and audit events (e.g., datetime.utcnow(), isoformat())",
        evidence=_evidence(scan, "has_timestamps"),
    ))

    # Check 4: Log integrity
    art.checks.append(CheckResult(
        name="log_integrity",
        status=Status.PASS if scan.has_log_integrity else Status.WARN,
        description="Log integrity protected (hashing, signatures, or append-only storage)",
        requirement="Logs that can be verified as unaltered (Art. 12(1))",
        recommendation=None if scan.has_log_integrity else
            "Add tamper evidence to logs (e.g., HMAC chains, hash signatures, append-only storage, or immutable log services)",
        evidence=_evidence(scan, "has_log_integrity"),
    ))

    return art


def check_article_14(scan: ScanResult) -> ArticleResult:
    """Article 14 — Human Oversight."""
    art = ArticleResult(article="Article 14", title="Human Oversight")

    # Check 1: Human review capability
    art.checks.append(CheckResult(
        name="human_review",
        status=Status.PASS if scan.has_human_review else Status.WARN,
        description="Human review flow exists for AI decisions",
        requirement="Enable individuals to fully understand the AI system (Art. 14(4)(a))",
        recommendation=None if scan.has_human_review else
            "Add a human review step for high-stakes AI decisions (e.g., approval queues, review status, moderator roles)",
        evidence=_evidence(scan, "has_human_review"),
    ))

    # Check 2: Override / kill switch
    art.checks.append(CheckResult(
        name="override_mechanism",
        status=Status.PASS if scan.has_override_mechanism else Status.FAIL,
        description="System can be overridden, disabled, or put in safe mode",
        requirement="Ability to intervene in or interrupt the system (Art. 14(4)(d))",
        recommendation=None if scan.has_override_mechanism else
            "Add an override or kill switch (e.g., enabled/disabled flag, dry_run mode, emergency stop)",
        evidence=_evidence(scan, "has_override_mechanism"),
    ))

    # Check 3: Notifications to humans
    art.checks.append(CheckResult(
        name="notification",
        status=Status.PASS if scan.has_notification else Status.WARN,
        description="Humans notified of important AI events or anomalies",
        requirement="Remain aware of possible tendency of the AI system (Art. 14(4)(b))",
        recommendation=None if scan.has_notification else
            "Add notifications for anomalies or important events (e.g., email alerts, Slack webhooks, monitoring dashboards)",
        evidence=_evidence(scan, "has_notification"),
    ))

    return art


def check_article_15(scan: ScanResult) -> ArticleResult:
    """Article 15 — Accuracy, Robustness, and Cybersecurity."""
    art = ArticleResult(article="Article 15", title="Accuracy, Robustness, and Cybersecurity")

    # Check 1: Input sanitization
    art.checks.append(CheckResult(
        name="input_sanitization",
        status=Status.PASS if scan.has_input_sanitization else Status.WARN,
        description="Inputs sanitized against injection and malicious content",
        requirement="Resilient against unauthorized third-party attempts to alter use (Art. 15(4))",
        recommendation=None if scan.has_input_sanitization else
            "Add input sanitization (e.g., bleach, markupsafe, regex filtering, allow/block lists)",
        evidence=_evidence(scan, "has_input_sanitization"),
    ))

    # Check 2: Error handling
    art.checks.append(CheckResult(
        name="error_handling",
        status=Status.PASS if scan.has_error_handling else Status.FAIL,
        description="Errors handled gracefully with try/except and recovery logic",
        requirement="Appropriate level of accuracy, robustness, and cybersecurity (Art. 15(1))",
        recommendation=None if scan.has_error_handling else
            "Add error handling (try/except blocks, custom exceptions, retry logic with tenacity/backoff)",
        evidence=_evidence(scan, "has_error_handling"),
    ))

    # Check 3: Testing
    art.checks.append(CheckResult(
        name="testing",
        status=Status.PASS if scan.has_testing else Status.FAIL,
        description="Test suite exists to validate system behavior",
        requirement="Tested with regard to accuracy and robustness (Art. 15(2))",
        recommendation=None if scan.has_testing else
            "Add tests (e.g., pytest, unittest) to validate AI behavior, edge cases, and failure modes",
        evidence=_evidence(scan, "has_testing"),
    ))

    # Check 4: Rate limiting
    art.checks.append(CheckResult(
        name="rate_limiting",
        status=Status.PASS if scan.has_rate_limiting else Status.WARN,
        description="Rate limiting or throttling protects against abuse",
        requirement="Resilient against attempts to manipulate (Art. 15(4))",
        recommendation=None if scan.has_rate_limiting else
            "Add rate limiting (e.g., slowapi, flask-limiter, custom token bucket, or API gateway limits)",
        evidence=_evidence(scan, "has_rate_limiting"),
    ))

    # Check 5: Dependency pinning
    art.checks.append(CheckResult(
        name="dependency_pinning",
        status=Status.PASS if scan.has_dependency_pinning else Status.WARN,
        description="Dependencies pinned to specific versions",
        requirement="Cybersecurity measures proportionate to risks (Art. 15(5))",
        recommendation=None if scan.has_dependency_pinning else
            "Pin dependency versions in requirements.txt or pyproject.toml (e.g., requests==2.31.0)",
        evidence=_evidence(scan, "has_dependency_pinning"),
    ))

    return art


def _evidence(scan: ScanResult, check: str) -> str | None:
    """Get evidence string for a check."""
    items = scan.evidence.get(check, [])
    if items:
        return "; ".join(items[:3])  # Show up to 3 evidence items
    return None


ALL_CHECKERS = [
    check_article_9,
    check_article_10,
    check_article_11,
    check_article_12,
    check_article_14,
    check_article_15,
]
