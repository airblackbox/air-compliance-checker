"""Tests for article-specific compliance checkers."""

import pytest
from air_compliance.models import Status
from air_compliance.scanner import ScanResult
from air_compliance.checkers import (
    check_article_9,
    check_article_10,
    check_article_11,
    check_article_12,
    check_article_14,
    check_article_15,
    ALL_CHECKERS,
)


@pytest.fixture
def empty_scan():
    return ScanResult()


@pytest.fixture
def full_scan():
    return ScanResult(
        has_langchain=True,
        has_audit_ledger=True,
        has_data_vault=True,
        has_consent_gate=True,
        has_injection_detector=True,
        has_trust_handler=True,
        has_trust_config=True,
        audit_hmac_enabled=True,
        injection_block_enabled=True,
        consent_mode="block_high_and_critical",
        vault_patterns=["ssn", "credit_card", "email"],
    )


class TestArticle9:
    def test_empty_project_fails(self, empty_scan):
        result = check_article_9(empty_scan)
        assert result.status == Status.FAIL
        assert result.fail_count >= 2

    def test_full_project_passes(self, full_scan):
        result = check_article_9(full_scan)
        assert result.status == Status.PASS
        assert result.fail_count == 0

    def test_has_four_checks(self, empty_scan):
        result = check_article_9(empty_scan)
        assert len(result.checks) == 4

    def test_partial_consent_gate_only(self):
        scan = ScanResult(has_consent_gate=True)
        result = check_article_9(scan)
        # consent_gate passes risk_classification and blocking_policy
        # but risk_config warns and risk_audit_trail fails
        pass_names = [c.name for c in result.checks if c.status == Status.PASS]
        assert "risk_classification" in pass_names
        assert "blocking_policy" in pass_names


class TestArticle10:
    def test_empty_project_fails(self, empty_scan):
        result = check_article_10(empty_scan)
        assert result.status == Status.FAIL

    def test_full_project_passes(self, full_scan):
        result = check_article_10(full_scan)
        assert result.status == Status.PASS

    def test_has_three_checks(self, empty_scan):
        result = check_article_10(empty_scan)
        assert len(result.checks) == 3

    def test_vault_without_patterns_warns(self):
        scan = ScanResult(has_data_vault=True)
        result = check_article_10(scan)
        # PII tokenization passes, data_minimization passes (defaults active)
        pii = [c for c in result.checks if c.name == "pii_tokenization"][0]
        assert pii.status == Status.PASS


class TestArticle11:
    def test_empty_project_fails(self, empty_scan):
        result = check_article_11(empty_scan)
        assert result.status == Status.FAIL

    def test_full_project_passes(self, full_scan):
        result = check_article_11(full_scan)
        assert result.status == Status.PASS

    def test_has_three_checks(self, empty_scan):
        result = check_article_11(empty_scan)
        assert len(result.checks) == 3


class TestArticle12:
    def test_empty_project_fails(self, empty_scan):
        result = check_article_12(empty_scan)
        assert result.status == Status.FAIL

    def test_full_project_passes(self, full_scan):
        result = check_article_12(full_scan)
        assert result.status == Status.PASS

    def test_has_four_checks(self, empty_scan):
        result = check_article_12(empty_scan)
        assert len(result.checks) == 4

    def test_tamper_evident_is_critical(self, empty_scan):
        """HMAC chain is the killer feature — should fail without it."""
        result = check_article_12(empty_scan)
        chain = [c for c in result.checks if c.name == "tamper_evident_chain"][0]
        assert chain.status == Status.FAIL
        assert "CRITICAL" in chain.recommendation


class TestArticle14:
    def test_empty_project_fails(self, empty_scan):
        result = check_article_14(empty_scan)
        assert result.status == Status.FAIL

    def test_full_project_passes(self, full_scan):
        result = check_article_14(full_scan)
        assert result.status == Status.PASS

    def test_has_four_checks(self, empty_scan):
        result = check_article_14(empty_scan)
        assert len(result.checks) == 4


class TestArticle15:
    def test_empty_project_fails(self, empty_scan):
        result = check_article_15(empty_scan)
        assert result.status == Status.FAIL

    def test_full_project_passes(self, full_scan):
        result = check_article_15(full_scan)
        assert result.status == Status.PASS

    def test_has_four_checks(self, empty_scan):
        result = check_article_15(empty_scan)
        assert len(result.checks) == 4

    def test_defense_in_depth_counts_layers(self):
        # 2 layers = WARN
        scan = ScanResult(has_injection_detector=True, has_audit_ledger=True)
        result = check_article_15(scan)
        did = [c for c in result.checks if c.name == "defense_in_depth"][0]
        assert did.status == Status.WARN
        assert "2/4" in did.description

        # 3 layers = PASS
        scan = ScanResult(has_injection_detector=True, has_audit_ledger=True, has_consent_gate=True)
        result = check_article_15(scan)
        did = [c for c in result.checks if c.name == "defense_in_depth"][0]
        assert did.status == Status.PASS

    def test_single_layer_fails(self):
        scan = ScanResult(has_audit_ledger=True)
        result = check_article_15(scan)
        did = [c for c in result.checks if c.name == "defense_in_depth"][0]
        assert did.status == Status.FAIL


class TestAllCheckers:
    def test_six_articles_covered(self):
        assert len(ALL_CHECKERS) == 6

    def test_all_return_article_result(self, empty_scan):
        for checker in ALL_CHECKERS:
            result = checker(empty_scan)
            assert hasattr(result, "article")
            assert hasattr(result, "checks")
            assert len(result.checks) > 0

    def test_full_project_all_pass(self, full_scan):
        for checker in ALL_CHECKERS:
            result = checker(full_scan)
            assert result.status == Status.PASS, f"{result.article} failed"