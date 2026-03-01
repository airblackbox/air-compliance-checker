"""Project scanner — detects real EU AI Act compliance patterns (tool-agnostic)."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class ScanResult:
    """What the scanner found in the project."""

    # ── Article 9: Risk Management ──
    has_risk_classification: bool = False     # Any risk/severity level system
    has_risk_config: bool = False             # Configurable risk thresholds
    has_access_control: bool = False          # Auth/permission checks on actions
    has_risk_audit: bool = False              # Risk decisions logged

    # ── Article 10: Data Governance ──
    has_input_validation: bool = False        # Pydantic, marshmallow, cerberus, etc.
    has_pii_handling: bool = False            # PII redaction, masking, or tokenization
    has_data_schemas: bool = False            # Typed/validated data models
    has_data_provenance: bool = False         # Tracking data sources/lineage

    # ── Article 11: Technical Documentation ──
    has_logging: bool = False                 # Any structured logging
    has_docstrings: bool = False              # Code documentation
    has_type_hints: bool = False              # Type annotations
    has_api_docs: bool = False                # OpenAPI, docstrings on endpoints

    # ── Article 12: Record-Keeping ──
    has_structured_logging: bool = False      # JSON/structured log format
    has_audit_trail: bool = False             # Explicit audit/event logging
    has_timestamps: bool = False              # Timestamped records
    has_log_integrity: bool = False           # HMAC, signatures, tamper evidence

    # ── Article 14: Human Oversight ──
    has_human_review: bool = False            # Manual approval/review flows
    has_override_mechanism: bool = False      # Kill switch, disable, override
    has_explainability: bool = False          # SHAP, LIME, feature importance
    has_notification: bool = False            # Alerts, notifications to humans

    # ── Article 15: Robustness & Security ──
    has_input_sanitization: bool = False      # Input cleaning/escaping
    has_error_handling: bool = False          # try/except, error boundaries
    has_testing: bool = False                 # pytest, unittest, test files
    has_rate_limiting: bool = False           # Rate limits, throttling
    has_dependency_pinning: bool = False      # Pinned versions in requirements

    # ── Frameworks detected ──
    frameworks_detected: list[str] = field(default_factory=list)

    # ── Files scanned ──
    python_files: list[str] = field(default_factory=list)
    config_files: list[str] = field(default_factory=list)
    requirement_files: list[str] = field(default_factory=list)
    test_files: list[str] = field(default_factory=list)

    # ── Evidence tracking ──
    evidence: dict[str, list[str]] = field(default_factory=lambda: {})

    def add_evidence(self, check: str, detail: str) -> None:
        """Add evidence for a check."""
        if check not in self.evidence:
            self.evidence[check] = []
        if detail not in self.evidence[check]:
            self.evidence[check].append(detail)


# ── Patterns that detect REAL compliance practices ──

FRAMEWORK_PATTERNS = {
    r"(?:from|import)\s+langchain": "LangChain",
    r"(?:from|import)\s+crewai": "CrewAI",
    r"(?:from|import)\s+autogen": "AutoGen",
    r"(?:from|import)\s+openai": "OpenAI",
    r"(?:from|import)\s+transformers": "HuggingFace Transformers",
    r"(?:from|import)\s+torch": "PyTorch",
    r"(?:from|import)\s+tensorflow": "TensorFlow",
    r"(?:from|import)\s+fastapi": "FastAPI",
    r"(?:from|import)\s+flask": "Flask",
    r"(?:from|import)\s+django": "Django",
}

# Article 9 — Risk Management
RISK_PATTERNS = {
    "has_risk_classification": [
        (r"(?:risk_level|severity|risk_score|threat_level|risk_rating)\s*[=:]", "Risk classification variable"),
        (r"(?:LOW|MEDIUM|HIGH|CRITICAL)\s*[=,\)]", "Risk level constants"),
        (r"risk.*(?:assess|evaluat|classif|categor)", "Risk assessment logic"),
    ],
    "has_risk_config": [
        (r"(?:risk|security|safety).*(?:config|setting|threshold|policy)", "Risk configuration"),
        (r"(?:max_retries|timeout|rate_limit|threshold)", "Safety thresholds"),
    ],
    "has_access_control": [
        (r"(?:@login_required|@permission|@requires_auth|@authorize|@protected)", "Auth decorator"),
        (r"(?:check_permission|has_permission|is_authorized|verify_token|authenticate)", "Permission check"),
        (r"(?:role|permission|scope|privilege)\s*(?:=|in\s|==)", "Role/permission logic"),
    ],
    "has_risk_audit": [
        (r"(?:audit|log).*(?:risk|decision|action|event)", "Risk decision logging"),
        (r"logger\.(?:info|warning|error|critical).*(?:risk|decision|deny|allow|block)", "Risk event logged"),
    ],
}

# Article 10 — Data Governance
DATA_PATTERNS = {
    "has_input_validation": [
        (r"(?:from|import)\s+pydantic", "Pydantic validation"),
        (r"(?:from|import)\s+marshmallow", "Marshmallow validation"),
        (r"(?:from|import)\s+cerberus", "Cerberus validation"),
        (r"(?:from|import)\s+voluptuous", "Voluptuous validation"),
        (r"(?:from|import)\s+jsonschema", "JSON Schema validation"),
        (r"class\s+\w+\(BaseModel\)", "Pydantic model"),
        (r"@validator|@field_validator|@model_validator", "Pydantic validator"),
        (r"Schema\(\{", "Schema definition"),
    ],
    "has_pii_handling": [
        (r"(?:pii|personal_data|sensitive|redact|mask|anonymiz|pseudonymiz|tokeniz)", "PII handling logic"),
        (r"(?:ssn|social_security|credit_card|phone_number|email_address).*(?:redact|mask|remove|strip)", "PII field handling"),
        (r"(?:from|import)\s+(?:presidio|scrubadub|faker)", "PII library"),
    ],
    "has_data_schemas": [
        (r"class\s+\w+\(BaseModel\)", "Pydantic model"),
        (r"class\s+\w+\(Schema\)", "Marshmallow schema"),
        (r"@dataclass", "Dataclass"),
        (r"TypedDict|NamedTuple", "Typed structure"),
    ],
    "has_data_provenance": [
        (r"(?:provenance|lineage|source|origin).*(?:track|record|log|store)", "Data provenance tracking"),
        (r"(?:data_source|source_url|source_id|document_id)", "Source tracking field"),
        (r"(?:sha256|hash|checksum|digest).*(?:data|document|content)", "Content hashing"),
    ],
}

# Article 11 — Technical Documentation
DOC_PATTERNS = {
    "has_logging": [
        (r"(?:from|import)\s+logging", "Python logging"),
        (r"(?:from|import)\s+structlog", "structlog"),
        (r"(?:from|import)\s+loguru", "loguru"),
        (r"logger\s*=\s*(?:logging\.getLogger|structlog\.get_logger|loguru)", "Logger instance"),
        (r"logger\.(?:info|debug|warning|error|critical)\(", "Log statement"),
    ],
    "has_type_hints": [
        (r"def\s+\w+\([^)]*:\s*\w+", "Function type hints"),
        (r"->\s*(?:str|int|float|bool|list|dict|None|Optional|Union|Any)", "Return type hint"),
    ],
}

# Article 12 — Record-Keeping
RECORD_PATTERNS = {
    "has_structured_logging": [
        (r"(?:from|import)\s+structlog", "structlog"),
        (r"(?:from|import)\s+(?:json_log|pythonjsonlogger|python_json_logger)", "JSON logger"),
        (r"logging\..*(?:JSONFormatter|json)", "JSON log format"),
        (r"(?:extra|context|bind)\s*=?\s*\{", "Structured log context"),
    ],
    "has_audit_trail": [
        (r"(?:audit|event).*(?:log|record|trail|store|write)", "Audit logging"),
        (r"(?:action|event|operation).*(?:created|logged|recorded|saved)", "Event recording"),
        (r"(?:from|import)\s+(?:auditlog|django_auditlog|audit)", "Audit library"),
    ],
    "has_timestamps": [
        (r"(?:datetime\.now|datetime\.utcnow|time\.time|timestamp)", "Timestamp generation"),
        (r"(?:created_at|updated_at|logged_at|event_time|timestamp)", "Timestamp field"),
        (r"isoformat|strftime", "Timestamp formatting"),
    ],
    "has_log_integrity": [
        (r"(?:hmac|hashlib\.sha256|hashlib\.sha512)", "Hash/HMAC for integrity"),
        (r"(?:sign|signature|verify|tamper|integrity)", "Integrity verification"),
        (r"(?:chain|previous_hash|prev_hash|block_hash)", "Chain verification"),
    ],
}

# Article 14 — Human Oversight
OVERSIGHT_PATTERNS = {
    "has_human_review": [
        (r"(?:review|approve|confirm|manual).*(?:required|needed|pending|queue)", "Human review flow"),
        (r"(?:status|state)\s*==?\s*['\"](?:pending_review|awaiting_approval|needs_review)", "Review status"),
        (r"(?:reviewer|approver|moderator)", "Reviewer role"),
    ],
    "has_override_mechanism": [
        (r"(?:override|disable|kill_switch|emergency_stop|force_stop|shutdown)", "Override mechanism"),
        (r"(?:enabled|active|running)\s*=\s*(?:False|True)", "Toggle control"),
        (r"(?:dry_run|sandbox|safe_mode|test_mode)", "Safe mode"),
    ],
    "has_explainability": [
        (r"(?:from|import)\s+(?:shap|lime|eli5|alibi|captum)", "Explainability library"),
        (r"(?:explain|feature_importance|attribution|interpret)", "Explainability logic"),
        (r"(?:reason|rationale|justification|explanation)\s*[=:]", "Decision explanation"),
    ],
    "has_notification": [
        (r"(?:notify|alert|send_email|send_slack|webhook)", "Notification mechanism"),
        (r"(?:from|import)\s+(?:smtplib|slack_sdk|twilio|sendgrid)", "Notification library"),
    ],
}

# Article 15 — Robustness & Security
SECURITY_PATTERNS = {
    "has_input_sanitization": [
        (r"(?:sanitiz|escap|clean|strip|bleach|purify)", "Input sanitization"),
        (r"(?:from|import)\s+(?:bleach|html|markupsafe)", "Sanitization library"),
        (r"(?:sql.*inject|xss|csrf|injection).*(?:prevent|protect|check|scan)", "Injection prevention"),
        (r"(?:allowlist|whitelist|blocklist|blacklist).*(?:check|filter|validate)", "Allow/block list"),
    ],
    "has_error_handling": [
        (r"try\s*:", "Try block"),
        (r"except\s+\w+", "Exception handler"),
        (r"raise\s+\w+Error|raise\s+\w+Exception", "Custom exception"),
        (r"(?:from|import)\s+(?:tenacity|retry|backoff)", "Retry library"),
    ],
    "has_rate_limiting": [
        (r"(?:rate_limit|throttl|cooldown|backoff|retry_after)", "Rate limiting"),
        (r"(?:from|import)\s+(?:ratelimit|slowapi|flask_limiter|throttle)", "Rate limit library"),
        (r"(?:max_requests|requests_per|tokens_per_minute|rpm|tpm)", "Rate config"),
    ],
}


class ProjectScanner:
    """Scans a project directory for EU AI Act compliance patterns (tool-agnostic)."""

    def __init__(self, project_path: str):
        self.project_path = Path(project_path).resolve()
        if not self.project_path.exists():
            raise FileNotFoundError(f"Project path not found: {self.project_path}")

    def scan(self) -> ScanResult:
        """Scan the project and return findings."""
        result = ScanResult()

        # Collect files
        result.python_files = self._find_files("*.py")
        result.config_files = (
            self._find_files("*.yaml")
            + self._find_files("*.yml")
            + self._find_files("*.toml")
            + self._find_files("*.json")
            + self._find_files("*.ini")
            + self._find_files("*.cfg")
        )
        result.requirement_files = (
            self._find_files("requirements*.txt")
            + self._find_files("pyproject.toml")
            + self._find_files("setup.py")
            + self._find_files("setup.cfg")
            + self._find_files("Pipfile")
        )
        result.test_files = self._find_test_files()

        # Scan Python files
        docstring_count = 0
        function_count = 0
        for py_file in result.python_files:
            content = self._read_file(py_file)
            if content is None:
                continue

            # Detect frameworks
            self._scan_frameworks(content, result)

            # Check all compliance patterns
            self._scan_patterns(content, result, RISK_PATTERNS)
            self._scan_patterns(content, result, DATA_PATTERNS)
            self._scan_patterns(content, result, DOC_PATTERNS)
            self._scan_patterns(content, result, RECORD_PATTERNS)
            self._scan_patterns(content, result, OVERSIGHT_PATTERNS)
            self._scan_patterns(content, result, SECURITY_PATTERNS)

            # Count docstrings and functions for documentation check
            docstring_count += len(re.findall(r'"""[\s\S]*?"""|\'\'\'[\s\S]*?\'\'\'', content))
            function_count += len(re.findall(r'def\s+\w+\(', content))

        # Docstring coverage check
        if function_count > 0 and docstring_count / max(function_count, 1) >= 0.3:
            result.has_docstrings = True
            result.add_evidence("has_docstrings", f"{docstring_count} docstrings across {function_count} functions")

        # Testing check — look for test files
        if result.test_files:
            result.has_testing = True
            result.add_evidence("has_testing", f"{len(result.test_files)} test files found")

        # Dependency pinning check
        for req_file in result.requirement_files:
            content = self._read_file(req_file)
            if content and re.search(r"==\d+\.\d+", content):
                result.has_dependency_pinning = True
                result.add_evidence("has_dependency_pinning", f"Pinned versions in {Path(req_file).name}")
                break

        # Check for API docs (OpenAPI, swagger)
        for cfg_file in result.config_files:
            content = self._read_file(cfg_file)
            if content and re.search(r"(?:openapi|swagger|api.*spec)", content, re.IGNORECASE):
                result.has_api_docs = True
                result.add_evidence("has_api_docs", f"API spec in {Path(cfg_file).name}")

        # Also check for README/docs
        doc_files = self._find_files("*.md") + self._find_files("*.rst")
        if doc_files:
            result.add_evidence("has_docstrings", f"{len(doc_files)} documentation files found")

        return result

    def _find_files(self, pattern: str) -> list[str]:
        """Find files matching a glob pattern, excluding noise directories."""
        exclude = {
            ".git", "node_modules", "__pycache__", ".venv", "venv",
            ".tox", "dist", "build", ".egg-info", ".eggs", ".mypy_cache",
            ".pytest_cache", ".ruff_cache", "htmlcov", "site-packages",
        }
        matches = []
        for path in self.project_path.rglob(pattern):
            if any(part in exclude for part in path.parts):
                continue
            matches.append(str(path))
        return matches

    def _find_test_files(self) -> list[str]:
        """Find test files."""
        test_files = []
        for py_file in self._find_files("*.py"):
            name = Path(py_file).name
            if name.startswith("test_") or name.endswith("_test.py") or "/tests/" in py_file:
                test_files.append(py_file)
        return test_files

    def _read_file(self, filepath: str) -> Optional[str]:
        """Read file contents, return None on error."""
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                return f.read()
        except (OSError, PermissionError):
            return None

    def _scan_frameworks(self, content: str, result: ScanResult) -> None:
        """Detect AI/ML frameworks."""
        for pattern, name in FRAMEWORK_PATTERNS.items():
            if re.search(pattern, content) and name not in result.frameworks_detected:
                result.frameworks_detected.append(name)

    def _scan_patterns(
        self,
        content: str,
        result: ScanResult,
        pattern_groups: dict[str, list[tuple[str, str]]],
    ) -> None:
        """Scan content against a group of compliance patterns."""
        for attr, patterns in pattern_groups.items():
            for regex, description in patterns:
                if re.search(regex, content, re.IGNORECASE):
                    setattr(result, attr, True)
                    result.add_evidence(attr, description)
