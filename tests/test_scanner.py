"""Tests for the project scanner (tool-agnostic)."""

import pytest
from air_compliance.scanner import ProjectScanner, ScanResult


@pytest.fixture
def temp_project(tmp_path):
    """Create a temporary project directory."""
    return tmp_path


class TestScanResult:
    def test_empty_result(self):
        result = ScanResult()
        assert result.frameworks_detected == []
        assert result.has_logging is False
        assert result.has_testing is False

    def test_evidence_tracking(self):
        result = ScanResult()
        result.add_evidence("has_logging", "Python logging")
        result.add_evidence("has_logging", "Logger instance")
        assert len(result.evidence["has_logging"]) == 2

    def test_no_duplicate_evidence(self):
        result = ScanResult()
        result.add_evidence("has_logging", "Python logging")
        result.add_evidence("has_logging", "Python logging")
        assert len(result.evidence["has_logging"]) == 1


class TestProjectScanner:
    def test_nonexistent_path(self):
        with pytest.raises(FileNotFoundError):
            ProjectScanner("/nonexistent/path/12345")

    def test_empty_project(self, temp_project):
        scanner = ProjectScanner(str(temp_project))
        result = scanner.scan()
        assert result.frameworks_detected == []
        assert result.has_logging is False

    def test_detects_logging(self, temp_project):
        py_file = temp_project / "app.py"
        py_file.write_text("import logging\nlogger = logging.getLogger(__name__)\nlogger.info('hello')\n")
        scanner = ProjectScanner(str(temp_project))
        result = scanner.scan()
        assert result.has_logging is True

    def test_detects_structlog(self, temp_project):
        py_file = temp_project / "app.py"
        py_file.write_text("import structlog\nlogger = structlog.get_logger()\n")
        scanner = ProjectScanner(str(temp_project))
        result = scanner.scan()
        assert result.has_logging is True
        assert result.has_structured_logging is True

    def test_detects_pydantic(self, temp_project):
        py_file = temp_project / "models.py"
        py_file.write_text("from pydantic import BaseModel\n\nclass User(BaseModel):\n    name: str\n")
        scanner = ProjectScanner(str(temp_project))
        result = scanner.scan()
        assert result.has_input_validation is True
        assert result.has_data_schemas is True

    def test_detects_error_handling(self, temp_project):
        py_file = temp_project / "app.py"
        py_file.write_text("try:\n    do_something()\nexcept ValueError as e:\n    handle(e)\n")
        scanner = ProjectScanner(str(temp_project))
        result = scanner.scan()
        assert result.has_error_handling is True

    def test_detects_tests(self, temp_project):
        tests_dir = temp_project / "tests"
        tests_dir.mkdir()
        test_file = tests_dir / "test_app.py"
        test_file.write_text("def test_something():\n    assert True\n")
        scanner = ProjectScanner(str(temp_project))
        result = scanner.scan()
        assert result.has_testing is True

    def test_detects_type_hints(self, temp_project):
        py_file = temp_project / "app.py"
        py_file.write_text("def greet(name: str) -> str:\n    return f'Hello {name}'\n")
        scanner = ProjectScanner(str(temp_project))
        result = scanner.scan()
        assert result.has_type_hints is True

    def test_detects_framework_langchain(self, temp_project):
        py_file = temp_project / "app.py"
        py_file.write_text("from langchain import LLMChain\n")
        scanner = ProjectScanner(str(temp_project))
        result = scanner.scan()
        assert "LangChain" in result.frameworks_detected

    def test_detects_framework_fastapi(self, temp_project):
        py_file = temp_project / "app.py"
        py_file.write_text("from fastapi import FastAPI\n")
        scanner = ProjectScanner(str(temp_project))
        result = scanner.scan()
        assert "FastAPI" in result.frameworks_detected

    def test_detects_access_control(self, temp_project):
        py_file = temp_project / "app.py"
        py_file.write_text("@login_required\ndef admin_view():\n    pass\n")
        scanner = ProjectScanner(str(temp_project))
        result = scanner.scan()
        assert result.has_access_control is True

    def test_detects_timestamps(self, temp_project):
        py_file = temp_project / "app.py"
        py_file.write_text("from datetime import datetime\ncreated_at = datetime.utcnow()\n")
        scanner = ProjectScanner(str(temp_project))
        result = scanner.scan()
        assert result.has_timestamps is True

    def test_detects_dependency_pinning(self, temp_project):
        req = temp_project / "requirements.txt"
        req.write_text("requests==2.31.0\npydantic==2.5.0\n")
        scanner = ProjectScanner(str(temp_project))
        result = scanner.scan()
        assert result.has_dependency_pinning is True

    def test_detects_override_mechanism(self, temp_project):
        py_file = temp_project / "app.py"
        py_file.write_text("enabled = True\ndry_run = False\n")
        scanner = ProjectScanner(str(temp_project))
        result = scanner.scan()
        assert result.has_override_mechanism is True

    def test_ignores_git_directory(self, temp_project):
        git_dir = temp_project / ".git"
        git_dir.mkdir()
        py_file = git_dir / "hooks.py"
        py_file.write_text("import logging\n")
        scanner = ProjectScanner(str(temp_project))
        result = scanner.scan()
        assert result.has_logging is False

    def test_ignores_node_modules(self, temp_project):
        nm = temp_project / "node_modules" / "pkg"
        nm.mkdir(parents=True)
        py_file = nm / "script.py"
        py_file.write_text("from pydantic import BaseModel\n")
        scanner = ProjectScanner(str(temp_project))
        result = scanner.scan()
        assert result.has_input_validation is False

    def test_docstring_coverage(self, temp_project):
        py_file = temp_project / "app.py"
        py_file.write_text(
            '"""Module doc."""\n'
            'def foo():\n    """Foo doc."""\n    pass\n'
            'def bar():\n    """Bar doc."""\n    pass\n'
            'def baz():\n    pass\n'
        )
        scanner = ProjectScanner(str(temp_project))
        result = scanner.scan()
        assert result.has_docstrings is True


class TestFullCompliantProject:
    """Test scanning a project with standard tools (no AIR Blackbox)."""

    def test_standard_tools_project(self, temp_project):
        # Main app with standard Python tools
        app = temp_project / "app.py"
        app.write_text(
            '"""Main application module."""\n'
            'import logging\n'
            'import structlog\n'
            'from datetime import datetime\n'
            'from pydantic import BaseModel\n\n'
            'logger = structlog.get_logger()\n\n'
            'class UserInput(BaseModel):\n'
            '    """Validates user input."""\n'
            '    query: str\n'
            '    risk_level: str = "LOW"\n\n'
            'def process(input_data: UserInput) -> str:\n'
            '    """Process user input with risk classification."""\n'
            '    created_at = datetime.utcnow()\n'
            '    logger.info("processing", risk_level=input_data.risk_level, timestamp=created_at.isoformat())\n'
            '    try:\n'
            '        result = do_ai_stuff(input_data)\n'
            '        logger.info("audit_event", action="process", result="success")\n'
            '        return result\n'
            '    except ValueError as e:\n'
            '        logger.error("processing_failed", error=str(e))\n'
            '        raise\n\n'
            'enabled = True\n'
            'dry_run = False\n\n'
            '@login_required\n'
            'def admin_action():\n'
            '    """Admin-only action with access control."""\n'
            '    pass\n'
        )

        # Requirements with pinned versions
        req = temp_project / "requirements.txt"
        req.write_text("pydantic==2.5.0\nstructlog==24.1.0\nfastapi==0.108.0\n")

        # Test file
        tests_dir = temp_project / "tests"
        tests_dir.mkdir()
        test_file = tests_dir / "test_app.py"
        test_file.write_text("def test_process():\n    assert True\n")

        scanner = ProjectScanner(str(temp_project))
        result = scanner.scan()

        # All major checks should pass with standard tools
        assert result.has_logging is True
        assert result.has_structured_logging is True
        assert result.has_input_validation is True
        assert result.has_data_schemas is True
        assert result.has_error_handling is True
        assert result.has_testing is True
        assert result.has_type_hints is True
        assert result.has_timestamps is True
        assert result.has_docstrings is True
        assert result.has_dependency_pinning is True
        assert result.has_access_control is True
        assert result.has_override_mechanism is True
        assert result.has_risk_classification is True
