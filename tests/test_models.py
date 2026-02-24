"""Tests for compliance report models."""

import pytest
from air_compliance.models import Status, CheckResult, ArticleResult, ComplianceReport


class TestStatus:
    def test_values(self):
        assert Status.PASS.value == "pass"
        assert Status.FAIL.value == "fail"
        assert Status.WARN.value == "warn"
        assert Status.SKIP.value == "skip"


class TestCheckResult:
    def test_basic(self):
        check = CheckResult(
            name="test_check",
            status=Status.PASS,
            description="A test check",
            requirement="Must do X",
        )
        assert check.name == "test_check"
        assert check.status == Status.PASS
        assert check.recommendation is None
        assert check.evidence is None

    def test_with_recommendation(self):
        check = CheckResult(
            name="failing_check",
            status=Status.FAIL,
            description="A failing check",
            requirement="Must do Y",
            recommendation="Add component Z",
        )
        assert check.recommendation == "Add component Z"


class TestArticleResult:
    def test_all_pass(self):
        art = ArticleResult(article="Article 9", title="Risk Management")
        art.checks = [
            CheckResult("a", Status.PASS, "d", "r"),
            CheckResult("b", Status.PASS, "d", "r"),
        ]
        assert art.status == Status.PASS
        assert art.pass_count == 2
        assert art.fail_count == 0

    def test_any_fail_means_fail(self):
        art = ArticleResult(article="Article 9", title="Risk Management")
        art.checks = [
            CheckResult("a", Status.PASS, "d", "r"),
            CheckResult("b", Status.FAIL, "d", "r"),
        ]
        assert art.status == Status.FAIL
        assert art.pass_count == 1
        assert art.fail_count == 1

    def test_warn_without_fail(self):
        art = ArticleResult(article="Article 9", title="Risk Management")
        art.checks = [
            CheckResult("a", Status.PASS, "d", "r"),
            CheckResult("b", Status.WARN, "d", "r"),
        ]
        assert art.status == Status.WARN
        assert art.warn_count == 1

    def test_all_skip(self):
        art = ArticleResult(article="Article 9", title="Risk Management")
        art.checks = [
            CheckResult("a", Status.SKIP, "d", "r"),
        ]
        assert art.status == Status.SKIP

    def test_fail_trumps_warn(self):
        art = ArticleResult(article="Article 9", title="Risk Management")
        art.checks = [
            CheckResult("a", Status.WARN, "d", "r"),
            CheckResult("b", Status.FAIL, "d", "r"),
        ]
        assert art.status == Status.FAIL


class TestComplianceReport:
    def test_empty_report(self):
        report = ComplianceReport(project_path="/test")
        assert report.total_checks == 0
        assert report.coverage_pct == 0.0

    def test_overall_pass(self):
        art = ArticleResult(article="Article 9", title="Risk Management")
        art.checks = [CheckResult("a", Status.PASS, "d", "r")]
        report = ComplianceReport(project_path="/test", articles=[art])
        assert report.overall_status == Status.PASS
        assert report.coverage_pct == 100.0

    def test_overall_fail(self):
        art = ArticleResult(article="Article 9", title="Risk Management")
        art.checks = [
            CheckResult("a", Status.PASS, "d", "r"),
            CheckResult("b", Status.FAIL, "d", "r"),
        ]
        report = ComplianceReport(project_path="/test", articles=[art])
        assert report.overall_status == Status.FAIL
        assert report.total_pass == 1
        assert report.total_fail == 1
        assert report.coverage_pct == 50.0

    def test_coverage_includes_warn(self):
        art = ArticleResult(article="Article 9", title="Risk Management")
        art.checks = [
            CheckResult("a", Status.PASS, "d", "r"),
            CheckResult("b", Status.WARN, "d", "r"),
            CheckResult("c", Status.FAIL, "d", "r"),
        ]
        report = ComplianceReport(project_path="/test", articles=[art])
        # 2 out of 3 pass or warn
        assert report.coverage_pct == pytest.approx(66.67, abs=0.01)