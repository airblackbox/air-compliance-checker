"""Tests for article-specific compliance checkers (tool-agnostic)."""

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
    """A project using standard Python tools — fully compliant."""
    return ScanResult(
        # Article 9
        has_risk_classification=True,
        has_risk_config=True,
        has_access_control=True,
        has_risk_audit=True,
        # Article 10
        has_input_validation=True,
        has_pii_handling=True,
        has_data_schemas=True,
        has_data_provenance=True,
        # Article 11
        has_logging=True,
        has_docstrings=True,
        has_type_hints=True,
        has_api_docs=True,
        # Article 12
        has_structured_logging=True,
        has_audit_trail=True,
        has_timestamps=True,
        has_log_integrity=True,
        # Article 14
        has_human_review=True,
        has_override_mechanism=True,
        has_explainability=True,
        has_notification=True,
        # Article 15
        has_input_sanitization=True,
        has_error_handling=True,
        has_testing=True,
        has_rate_limiting=True,
        has_dependency_pinning=True,
    )


class TestArticle9:
    def test_empty_project_fails(self, empty_scan):
        result = check_article_9(empty_scan)
        assert result.status == Status.FAIL

    def test_full_project_passes(self, full_scan):
        result = check_article_9(full_scan)
        assert result.status == Status.PASS
        assert result.fail_count == 0

    def test_has_three_checks(self, empty_scan):
        result = check_article_9(empty_scan)
        assert len(result.checks) == 3

    def test_recommendations_are_tool_agnostic(self, empty_scan):
        result = check_article_9(empty_scan)
        for check in result.checks:
            if check.recommendation:
                assert "ConsentGate" not in check.recommendation
                assert "AIR" not in check.recommendation
                assert "AirTrust" not in check.recommendation


class TestArticle10:
    def test_empty_project_fails(self, empty_scan):
        result = check_article_10(empty_scan)
        assert result.status == Status.FAIL

    def test_full_project_passes(self, full_scan):
        result = check_article_10(full_scan)
        assert result.status == Status.PASS

    def test_has_four_checks(self, empty_scan):
        result = check_article_10(empty_scan)
        assert len(result.checks) == 4

    def test_recommendations_are_tool_agnostic(self, empty_scan):
        result = check_article_10(empty_scan)
        for check in result.checks:
            if check.recommendation:
                assert "DataVault" not in check.recommendation
                assert "AIR" not in check.recommendation


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

    def test_recommendations_are_tool_agnostic(self, empty_scan):
        result = check_article_11(empty_scan)
        for check in result.checks:
            if check.recommendation:
                assert "AuditLedger" not in check.recommendation
                assert "AIR" not in check.recommendation


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

    def test_recommendations_are_tool_agnostic(self, empty_scan):
        result = check_article_12(empty_scan)
        for check in result.checks:
            if check.recommendation:
                assert "AuditLedger" not in check.recommendation
                assert "AIR" not in check.recommendation


class TestArticle14:
    def test_empty_project_fails(self, empty_scan):
        result = check_article_14(empty_scan)
        assert result.status == Status.FAIL

    def test_full_project_passes(self, full_scan):
        result = check_article_14(full_scan)
        assert result.status == Status.PASS

    def test_has_three_checks(self, empty_scan):
        result = check_article_14(empty_scan)
        assert len(result.checks) == 3

    def test_recommendations_are_tool_agnostic(self, empty_scan):
        result = check_article_14(empty_scan)
        for check in result.checks:
            if check.recommendation:
                assert "ConsentGate" not in check.recommendation
                assert "AIR" not in check.recommendation


class TestArticle15:
    def test_empty_project_fails(self, empty_scan):
        result = check_article_15(empty_scan)
        assert result.status == Status.FAIL

    def test_full_project_passes(self, full_scan):
        result = check_article_15(full_scan)
        assert result.status == Status.PASS

    def test_has_five_checks(self, empty_scan):
        result = check_article_15(empty_scan)
        assert len(result.checks) == 5

    def test_recommendations_are_tool_agnostic(self, empty_scan):
        result = check_article_15(empty_scan)
        for check in result.checks:
            if check.recommendation:
                assert "InjectionDetector" not in check.recommendation
                assert "AIR" not in check.recommendation


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

    def test_no_air_blackbox_references(self, empty_scan):
        """Ensure no recommendations reference AIR Blackbox products."""
        for checker in ALL_CHECKERS:
            result = checker(empty_scan)
            for check in result.checks:
                if check.recommendation:
                    assert "ConsentGate" not in check.recommendation
                    assert "DataVault" not in check.recommendation
                    assert "AuditLedger" not in check.recommendation
                    assert "InjectionDetector" not in check.recommendation
                    assert "AirTrust" not in check.recommendation
                    assert "air-langchain" not in check.recommendation
                    assert "air-crewai" not in check.recommendation
                    assert "air-rag" not in check.recommendation
