"""Tests for the CLI interface."""

import json
import pytest
from pathlib import Path

from air_compliance.cli import run_scan, main
from air_compliance.models import Status


@pytest.fixture
def empty_project(tmp_path):
    return str(tmp_path)


@pytest.fixture
def compliant_project(tmp_path):
    """A fully compliant project using standard Python tools."""
    app = tmp_path / "app.py"
    app.write_text(
        '"""Main application."""\n'
        'import logging\n'
        'import structlog\n'
        'from datetime import datetime\n'
        'from pydantic import BaseModel, field_validator\n\n'
        'logger = structlog.get_logger()\n\n'
        'class Input(BaseModel):\n'
        '    """Input validation model."""\n'
        '    query: str\n'
        '    risk_level: str = "LOW"\n\n'
        'def process(data: Input) -> str:\n'
        '    """Process data with logging and error handling."""\n'
        '    created_at = datetime.utcnow()\n'
        '    logger.info("audit_event", action="process", timestamp=created_at.isoformat())\n'
        '    try:\n'
        '        result = do_work(data)\n'
        '        return result\n'
        '    except ValueError as e:\n'
        '        logger.error("failed", error=str(e))\n'
        '        raise\n\n'
        'enabled = True\n'
        'dry_run = False\n\n'
        '@login_required\n'
        'def admin():\n'
        '    """Admin action."""\n'
        '    pass\n'
    )

    req = tmp_path / "requirements.txt"
    req.write_text("pydantic==2.5.0\nstructlog==24.1.0\n")

    tests_dir = tmp_path / "tests"
    tests_dir.mkdir()
    test_file = tests_dir / "test_app.py"
    test_file.write_text("def test_something():\n    assert True\n")

    return str(tmp_path)


class TestRunScan:
    def test_empty_project(self, empty_project):
        report = run_scan(empty_project)
        assert report.overall_status == Status.FAIL
        assert report.total_fail > 0
        assert report.frameworks_detected == []

    def test_compliant_project(self, compliant_project):
        report = run_scan(compliant_project)
        # May have some warnings but no failures
        assert report.total_fail == 0

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
        assert len(data["articles"]) == 6

    def test_strict_mode_fails(self, empty_project, monkeypatch):
        monkeypatch.setattr("sys.argv", ["air-compliance", empty_project, "--strict"])
        exit_code = main()
        assert exit_code == 1

    def test_strict_mode_passes(self, compliant_project, monkeypatch):
        monkeypatch.setattr("sys.argv", ["air-compliance", compliant_project, "--strict"])
        exit_code = main()
        assert exit_code == 0

    def test_no_air_blackbox_in_output(self, empty_project, capsys, monkeypatch):
        """Ensure CLI output doesn't reference AIR Blackbox products."""
        monkeypatch.setattr("sys.argv", ["air-compliance", empty_project])
        main()
        captured = capsys.readouterr()
        assert "ConsentGate" not in captured.out
        assert "DataVault" not in captured.out
        assert "AuditLedger" not in captured.out
        assert "InjectionDetector" not in captured.out
        assert "AirTrust" not in captured.out
