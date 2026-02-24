"""Article-specific compliance checkers for EU AI Act."""

from __future__ import annotations

from air_compliance.models import ArticleResult, CheckResult, Status
from air_compliance.scanner import ScanResult


def check_article_9(scan: ScanResult) -> ArticleResult:
    """Article 9 — Risk Management System."""
    art = ArticleResult(article="Article 9", title="Risk Management System")

    # Check 1: Risk classification exists
    art.checks.append(CheckResult(
        name="risk_classification",
        status=Status.PASS if scan.has_consent_gate else Status.FAIL,
        description="Tool calls classified by risk level",
        requirement="Identify and analyze known and foreseeable risks",
        recommendation=None if scan.has_consent_gate else "Add ConsentGate to classify tool calls by risk level (LOW/MEDIUM/HIGH/CRITICAL)",
        evidence="ConsentGate detected" if scan.has_consent_gate else None,
    ))

    # Check 2: Configurable risk levels
    art.checks.append(CheckResult(
        name="risk_config",
        status=Status.PASS if scan.has_trust_config else Status.WARN,
        description="Risk levels configurable per tool",
        requirement="Estimate and evaluate risks from intended use",
        recommendation=None if scan.has_trust_config else "Add AirTrustConfig with tool_risk_levels to customize risk per tool",
        evidence="AirTrustConfig detected" if scan.has_trust_config else None,
    ))

    # Check 3: Blocking policies active
    has_blocking = scan.consent_mode is not None or scan.has_consent_gate
    art.checks.append(CheckResult(
        name="blocking_policy",
        status=Status.PASS if has_blocking else Status.FAIL,
        description="Risk-based blocking policy enforced at runtime",
        requirement="Adopt suitable risk management measures",
        recommendation=None if has_blocking else "Configure consent_mode (BLOCK_ALL, BLOCK_CRITICAL, BLOCK_HIGH_AND_CRITICAL)",
        evidence=f"Consent mode: {scan.consent_mode}" if scan.consent_mode else ("ConsentGate active" if scan.has_consent_gate else None),
    ))

    # Check 4: Audit trail for risk decisions
    art.checks.append(CheckResult(
        name="risk_audit_trail",
        status=Status.PASS if scan.has_audit_ledger else Status.FAIL,
        description="Risk decisions logged to audit trail",
        requirement="Demonstrate residual risk is below acceptable level",
        recommendation=None if scan.has_audit_ledger else "Add AuditLedger to log all risk classification and blocking decisions",
        evidence="AuditLedger detected" if scan.has_audit_ledger else None,
    ))

    return art


def check_article_10(scan: ScanResult) -> ArticleResult:
    """Article 10 — Data and Data Governance."""
    art = ArticleResult(article="Article 10", title="Data and Data Governance")

    # Check 1: PII tokenization
    art.checks.append(CheckResult(
        name="pii_tokenization",
        status=Status.PASS if scan.has_data_vault else Status.FAIL,
        description="PII automatically tokenized before reaching the LLM",
        requirement="Data governance and management practices",
        recommendation=None if scan.has_data_vault else "Add DataVault to tokenize sensitive data (SSN, credit card, email, API keys)",
        evidence="DataVault detected" if scan.has_data_vault else None,
    ))

    # Check 2: Data minimization patterns
    has_patterns = len(scan.vault_patterns) > 0 or scan.has_data_vault
    art.checks.append(CheckResult(
        name="data_minimization",
        status=Status.PASS if has_patterns else Status.WARN,
        description="Sensitive data patterns configured for redaction",
        requirement="Appropriate data minimization measures",
        recommendation=None if has_patterns else "Configure DataVault patterns for your data types (ssn, credit_card, email, api_key, phone)",
        evidence=f"Vault patterns: {', '.join(scan.vault_patterns)}" if scan.vault_patterns else ("DataVault defaults active" if scan.has_data_vault else None),
    ))

    # Check 3: Prompt logging for bias analysis
    art.checks.append(CheckResult(
        name="prompt_logging",
        status=Status.PASS if scan.has_audit_ledger and scan.has_trust_handler else Status.WARN,
        description="Prompts logged for post-hoc bias examination",
        requirement="Examination for possible biases",
        recommendation=None if (scan.has_audit_ledger and scan.has_trust_handler) else "Enable audit logging with trust handler to capture all prompts for bias analysis",
        evidence="AuditLedger + TrustHandler active" if (scan.has_audit_ledger and scan.has_trust_handler) else None,
    ))

    return art


def check_article_11(scan: ScanResult) -> ArticleResult:
    """Article 11 — Technical Documentation."""
    art = ArticleResult(article="Article 11", title="Technical Documentation")

    # Check 1: Structured audit logging
    art.checks.append(CheckResult(
        name="structured_logging",
        status=Status.PASS if scan.has_audit_ledger else Status.FAIL,
        description="Every operation documented with structured timestamps",
        requirement="General description of the AI system kept up to date",
        recommendation=None if scan.has_audit_ledger else "Add AuditLedger for structured logging of all agent operations",
        evidence="AuditLedger detected" if scan.has_audit_ledger else None,
    ))

    # Check 2: Full call graph
    art.checks.append(CheckResult(
        name="call_graph",
        status=Status.PASS if scan.has_trust_handler else Status.FAIL,
        description="Full call graph captured (chain → LLM → tool → result)",
        requirement="Detailed description of system elements and development process",
        recommendation=None if scan.has_trust_handler else "Add AirTrustCallbackHandler or AirTrustHook to capture complete call graphs",
        evidence="TrustHandler detected" if scan.has_trust_handler else None,
    ))

    # Check 3: Tamper-evident integrity
    art.checks.append(CheckResult(
        name="tamper_evidence",
        status=Status.PASS if scan.audit_hmac_enabled else Status.WARN,
        description="HMAC-SHA256 chain ensures log integrity",
        requirement="Monitoring, functioning, and control documentation",
        recommendation=None if scan.audit_hmac_enabled else "Configure HMAC secret key for tamper-evident audit chain (audit_secret in config)",
        evidence="HMAC signing detected" if scan.audit_hmac_enabled else None,
    ))

    return art


def check_article_12(scan: ScanResult) -> ArticleResult:
    """Article 12 — Record-Keeping."""
    art = ArticleResult(article="Article 12", title="Record-Keeping")

    # Check 1: Automatic event recording
    art.checks.append(CheckResult(
        name="auto_recording",
        status=Status.PASS if scan.has_audit_ledger else Status.FAIL,
        description="Events automatically recorded over system lifetime",
        requirement="Automatic recording of events (logs) over the lifetime of the system",
        recommendation=None if scan.has_audit_ledger else "Add AuditLedger for automatic event recording with ISO 8601 timestamps",
        evidence="AuditLedger detected" if scan.has_audit_ledger else None,
    ))

    # Check 2: Consent decision logging
    has_consent_log = scan.has_consent_gate and scan.has_audit_ledger
    art.checks.append(CheckResult(
        name="consent_logging",
        status=Status.PASS if has_consent_log else Status.FAIL,
        description="Consent decisions logged with tool name, risk level, allow/deny",
        requirement="Reference database against which input data is checked",
        recommendation=None if has_consent_log else "Enable both ConsentGate and AuditLedger to log all consent decisions",
        evidence="ConsentGate + AuditLedger active" if has_consent_log else None,
    ))

    # Check 3: Injection detection logging
    has_injection_log = scan.has_injection_detector and scan.has_audit_ledger
    art.checks.append(CheckResult(
        name="injection_logging",
        status=Status.PASS if has_injection_log else Status.WARN,
        description="Injection detection results logged with pattern and match",
        requirement="Input data for which the search has led to a match",
        recommendation=None if has_injection_log else "Enable InjectionDetector with AuditLedger to log all detection events",
        evidence="InjectionDetector + AuditLedger active" if has_injection_log else None,
    ))

    # Check 4: Tamper-evident chain (Article 12 killer feature)
    art.checks.append(CheckResult(
        name="tamper_evident_chain",
        status=Status.PASS if scan.audit_hmac_enabled else Status.FAIL,
        description="HMAC-SHA256 chained logs — mathematically verifiable integrity",
        requirement="Logs that regulators can verify haven't been altered",
        recommendation=None if scan.audit_hmac_enabled else "CRITICAL: Set audit_secret to enable HMAC-SHA256 tamper-evident chain. This is the Article 12 killer feature.",
        evidence="HMAC chain active" if scan.audit_hmac_enabled else None,
    ))

    return art


def check_article_14(scan: ScanResult) -> ArticleResult:
    """Article 14 — Human Oversight."""
    art = ArticleResult(article="Article 14", title="Human Oversight")

    # Check 1: Audit trail for human review
    art.checks.append(CheckResult(
        name="human_review",
        status=Status.PASS if scan.has_audit_ledger else Status.FAIL,
        description="Complete audit trail enables human review of agent actions",
        requirement="Enabling individuals to fully understand the AI system",
        recommendation=None if scan.has_audit_ledger else "Add AuditLedger so humans can review exactly what the agent did and why",
        evidence="AuditLedger detected" if scan.has_audit_ledger else None,
    ))

    # Check 2: Consent gate for human control
    art.checks.append(CheckResult(
        name="human_control",
        status=Status.PASS if scan.has_consent_gate else Status.FAIL,
        description="Humans define which tools the agent can use at what risk level",
        requirement="Ability to decide not to use or override the AI system",
        recommendation=None if scan.has_consent_gate else "Add ConsentGate so humans control which tools are allowed and at what risk threshold",
        evidence="ConsentGate detected" if scan.has_consent_gate else None,
    ))

    # Check 3: Exception-based intervention
    has_intervention = scan.has_consent_gate or scan.has_injection_detector
    art.checks.append(CheckResult(
        name="intervention_capability",
        status=Status.PASS if has_intervention else Status.FAIL,
        description="System can be interrupted via ConsentDeniedError / InjectionBlockedError",
        requirement="Ability to intervene in or interrupt the system",
        recommendation=None if has_intervention else "Add ConsentGate or InjectionDetector for exception-based execution blocking",
        evidence="Blocking capability detected" if has_intervention else None,
    ))

    # Check 4: Tokenized but visible decision flow
    has_visible_flow = scan.has_data_vault and scan.has_audit_ledger
    art.checks.append(CheckResult(
        name="interpretable_output",
        status=Status.PASS if has_visible_flow else Status.WARN,
        description="Sensitive data masked but decision flow remains visible",
        requirement="Enabling individuals to correctly interpret the output",
        recommendation=None if has_visible_flow else "Combine DataVault (PII masking) with AuditLedger (decision logging) for interpretable oversight",
        evidence="DataVault + AuditLedger active" if has_visible_flow else None,
    ))

    return art


def check_article_15(scan: ScanResult) -> ArticleResult:
    """Article 15 — Accuracy, Robustness, and Cybersecurity."""
    art = ArticleResult(article="Article 15", title="Accuracy, Robustness, and Cybersecurity")

    # Check 1: Injection detection
    art.checks.append(CheckResult(
        name="injection_defense",
        status=Status.PASS if scan.has_injection_detector else Status.FAIL,
        description="Prompts scanned for injection attacks before reaching the model",
        requirement="Resilient against unauthorized third-party attempts to alter use",
        recommendation=None if scan.has_injection_detector else "Add InjectionDetector to scan all prompts for injection attacks (7+ default patterns)",
        evidence="InjectionDetector detected" if scan.has_injection_detector else None,
    ))

    # Check 2: Injection blocking enabled
    art.checks.append(CheckResult(
        name="injection_blocking",
        status=Status.PASS if scan.injection_block_enabled else Status.WARN,
        description="Detected injection attacks actively blocked (not just logged)",
        requirement="AI system resilient against attempts to manipulate",
        recommendation=None if scan.injection_block_enabled else "Set injection block=True to actively block detected attacks, not just log them",
        evidence="Injection blocking enabled" if scan.injection_block_enabled else None,
    ))

    # Check 3: Multi-layer defense
    layers = sum([
        scan.has_injection_detector,
        scan.has_consent_gate,
        scan.has_data_vault,
        scan.has_audit_ledger,
    ])
    art.checks.append(CheckResult(
        name="defense_in_depth",
        status=Status.PASS if layers >= 3 else (Status.WARN if layers >= 2 else Status.FAIL),
        description=f"Defense in depth: {layers}/4 security layers active",
        requirement="Technically redundant solutions for safety",
        recommendation=None if layers >= 3 else f"Enable more security layers ({4 - layers} missing). Need: InjectionDetector, ConsentGate, DataVault, AuditLedger",
        evidence=f"{layers}/4 layers: " + ", ".join(scan.air_components_detected) if layers > 0 else None,
    ))

    # Check 4: Configurable security
    art.checks.append(CheckResult(
        name="configurable_security",
        status=Status.PASS if scan.has_trust_config else Status.WARN,
        description="Security measures configurable per deployment and threat model",
        requirement="Cybersecurity measures proportionate to risks",
        recommendation=None if scan.has_trust_config else "Add AirTrustConfig to adjust patterns, risk levels, and blocking modes per deployment",
        evidence="AirTrustConfig detected" if scan.has_trust_config else None,
    ))

    return art


ALL_CHECKERS = [
    check_article_9,
    check_article_10,
    check_article_11,
    check_article_12,
    check_article_14,
    check_article_15,
]