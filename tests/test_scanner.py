"""Tests for the project scanner."""

import os
import tempfile
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
        assert result.air_components_detected == []

    def test_framework_detection(self):
        result = ScanResult(has_langchain=True, has_crewai=True)
        assert "LangChain" in result.frameworks_detected
        assert "CrewAI" in result.frameworks_detected
        assert len(result.frameworks_detected) == 2

    def test_component_detection(self):
        result = ScanResult(
            has_audit_ledger=True,
            has_data_vault=True,
            has_consent_gate=True,
        )
        assert "AuditLedger" in result.air_components_detected
        assert "DataVault" in result.air_components_detected
        assert "ConsentGate" in result.air_components_detected


class TestProjectScanner:
    def test_nonexistent_path(self):
        with pytest.raises(FileNotFoundError):
            ProjectScanner("/nonexistent/path/12345")

    def test_empty_project(self, temp_project):
        scanner = ProjectScanner(str(temp_project))
        result = scanner.scan()
        assert result.frameworks_detected == []
        assert result.air_components_detected == []

    def test_detects_langchain_import(self, temp_project):
        py_file = temp_project / "app.py"
        py_file.write_text("from air_langchain_trust import AirTrustCallbackHandler\n")
        scanner = ProjectScanner(str(temp_project))
        result = scanner.scan()
        assert result.has_langchain is True
        assert result.has_trust_handler is True

    def test_detects_crewai_import(self, temp_project):
        py_file = temp_project / "app.py"
        py_file.write_text("from air_crewai_trust import activate_trust\n")
        scanner = ProjectScanner(str(temp_project))
        result = scanner.scan()
        assert result.has_crewai is True
        assert result.has_trust_handler is True

    def test_detects_all_components(self, temp_project):
        py_file = temp_project / "app.py"
        py_file.write_text(
            "from air_langchain_trust import AirTrustCallbackHandler\n"
            "from air_langchain_trust import AuditLedger, DataVault\n"
            "from air_langchain_trust import ConsentGate, InjectionDetector\n"
            "from air_langchain_trust import AirTrustConfig\n"
        )
        scanner = ProjectScanner(str(temp_project))
        result = scanner.scan()
        assert result.has_audit_ledger is True
        assert result.has_data_vault is True
        assert result.has_consent_gate is True
        assert result.has_injection_detector is True
        assert result.has_trust_handler is True
        assert result.has_trust_config is True

    def test_detects_requirements(self, temp_project):
        req = temp_project / "requirements.txt"
        req.write_text("air-langchain-trust>=0.1.0\nlangchain-core>=0.3.0\n")
        scanner = ProjectScanner(str(temp_project))
        result = scanner.scan()
        assert result.has_langchain is True

    def test_detects_docker_gateway(self, temp_project):
        dc = temp_project / "docker-compose.yml"
        dc.write_text("image: ghcr.io/airblackbox/gateway:main\n")
        scanner = ProjectScanner(str(temp_project))
        result = scanner.scan()
        assert result.has_gateway is True

    def test_detects_typescript(self, temp_project):
        pkg = temp_project / "package.json"
        pkg.write_text('{"dependencies": {"openclaw-air-trust": "^0.1.0"}}\n')
        scanner = ProjectScanner(str(temp_project))
        result = scanner.scan()
        assert result.has_typescript is True

    def test_detects_hmac_config(self, temp_project):
        cfg = temp_project / "config.yaml"
        cfg.write_text("audit:\n  secret_key: my-hmac-secret\n  enabled: true\n")
        scanner = ProjectScanner(str(temp_project))
        result = scanner.scan()
        assert result.audit_hmac_enabled is True

    def test_ignores_git_directory(self, temp_project):
        git_dir = temp_project / ".git"
        git_dir.mkdir()
        py_file = git_dir / "hooks.py"
        py_file.write_text("from langchain import something\n")
        scanner = ProjectScanner(str(temp_project))
        result = scanner.scan()
        assert result.has_langchain is False

    def test_ignores_node_modules(self, temp_project):
        nm = temp_project / "node_modules" / "pkg"
        nm.mkdir(parents=True)
        py_file = nm / "script.py"
        py_file.write_text("from crewai import Agent\n")
        scanner = ProjectScanner(str(temp_project))
        result = scanner.scan()
        assert result.has_crewai is False


class TestFullCompliantProject:
    """Test scanning a fully compliant project."""

    def test_full_project(self, temp_project):
        # Main app with all components
        app = temp_project / "app.py"
        app.write_text(
            "from air_langchain_trust import AirTrustCallbackHandler, AirTrustConfig\n"
            "from air_langchain_trust.audit_ledger import AuditLedger\n"
            "from air_langchain_trust.data_vault import DataVault\n"
            "from air_langchain_trust.consent_gate import ConsentGate\n"
            "from air_langchain_trust.injection_detector import InjectionDetector\n"
            "\n"
            "config = AirTrustConfig(\n"
            "    audit_secret='my-secret',\n"
            "    injection_block=True,\n"
            ")\n"
            "handler = AirTrustCallbackHandler(config=config)\n"
        )

        # Config file
        cfg = temp_project / "air-config.yaml"
        cfg.write_text(
            "audit:\n"
            "  enabled: true\n"
            "  secret_key: ${AUDIT_SECRET}\n"
            "vault:\n"
            "  patterns: ssn, credit_card, email, api_key\n"
            "consent:\n"
            "  consent_mode: block_high_and_critical\n"
            "injection:\n"
            "  block: True\n"
        )

        scanner = ProjectScanner(str(temp_project))
        result = scanner.scan()

        assert result.has_langchain is True
        assert result.has_audit_ledger is True
        assert result.has_data_vault is True
        assert result.has_consent_gate is True
        assert result.has_injection_detector is True
        assert result.has_trust_handler is True
        assert result.has_trust_config is True
        assert result.audit_hmac_enabled is True
        assert result.injection_block_enabled is True
        assert len(result.vault_patterns) > 0