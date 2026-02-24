"""Tests for the CLI interface."""

import json
import tempfile
import pytest
from pathlib import Path

from air_compliance.cli import run_scan, main
from air_compliance.models import Status


@pytest.fixture
def empty_project(tmp_path):
    return str(tmp_path)


@pytest.fixture
def compliant_project(tmp_path):
    """A fully compliant project."""
    app = tmp_path / "app.py"
    app.write_text(
        "from air_langchain_trust import AirTrustCallbackHandler, AirTrustConfig\n"
        "from air_langchain_trust.audit_ledger import AuditLedger\n"
        "from air_langchain_trust.data_vault import DataVault\n"
        "from air_langchain_trust.consent_gate import ConsentGate\n"
        "from air_langchain_trust.injection_detector import InjectionDetector\n"
        "\n"
        "config = AirTrustConfig(audit_secret='key', injection_block=True)\n"
        "handler = AirTrustCallbackHandler(config=config)\n"
    )
    cfg = tmp_path / "config.yaml"
    cfg.write_text(
        "audit:\n  secret_key: ${AUDIT_SECRET}\n"
        "vault:\n  patterns: ssn, email\n"
        "consent:\n  consent_mode: block_critical\n"
        "injection:\n  block: True\n"
    )
    return str(tmp_path)


class TestRunScan:
    def test_empty_project(self, empty_project):
        report = run_scan(empty_project)
        assert report.overall_status == Status.FAIL
        assert report.total_fail > 0
        assert report.frameworks_detected == []

    def test_compliant_project(self, compliant_project):
        report = run_scan(compliant_project)
        assert report.overall_status == Status.PASS
        assert report.total_fail == 0
        assert "LangChain" in report.frameworks_detected

    def test_nonexistent_path(self):
        with pytest.raises(FileNotFoundError):
            run_scan("/nonexistent/path/xyz")

    def test_report_has_all_articles(self, empty_project):
        report = run_scan(empty_project)
        articles = [a.article for a in report.articles]
        assert "Article 9" in articles
        assert "Article 10" in articles
        assert "Article 11" in articles
        assert "Article 12" in articles
        assert "Article 14" in articles
        assert "Article 15" in articles

    def test_coverage_pct(self, compliant_project):
        report = run_scan(compliant_project)
        assert report.coverage_pct == 100.0


class TestMainCLI:
    def test_version(self, capsys):
        with pytest.raises(SystemExit) as exc:
            import sys
            sys.argv = ["air-compliance", "--version"]
            main()
        assert exc.value.code == 0

    def test_json_output(self, compliant_project, capsys, monkeypatch):
        monkeypatch.setattr("sys.argv", ["air-compliance", compliant_project, "--json"])
        exit_code = main()
        assert exit_code == 0
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["overall_status"] == "pass"
        assert data["coverage_pct"] == 100.0
        assert len(data["articles"]) == 6

    def test_strict_mode_fails(self, empty_project, monkeypatch):
        monkeypatch.setattr("sys.argv", ["air-compliance", empty_project, "--strict"])
        exit_code = main()
        assert exit_code == 1

    def test_strict_mode_passes(self, compliant_project, monkeypatch):
        monkeypatch.setattr("sys.argv", ["air-compliance", compliant_project, "--strict"])
        exit_code = main()
        assert exit_code == 0