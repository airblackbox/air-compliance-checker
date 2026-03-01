"""Project scanner — detects AIR Blackbox components and configuration."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class ScanResult:
    """What the scanner found in the project."""
    # Frameworks detected
    has_langchain: bool = False
    has_crewai: bool = False
    has_openai_agents: bool = False
    has_autogen: bool = False
    has_typescript: bool = False
    has_gateway: bool = False
    has_rag_trust: bool = False

    # AIR components detected
    has_audit_ledger: bool = False
    has_data_vault: bool = False
    has_consent_gate: bool = False
    has_injection_detector: bool = False
    has_trust_handler: bool = False
    has_trust_config: bool = False
    has_provenance_tracker: bool = False
    has_write_gate: bool = False
    has_drift_detector: bool = False

    # Configuration details
    audit_hmac_enabled: bool = False
    vault_patterns: list[str] = field(default_factory=list)
    consent_mode: Optional[str] = None
    consent_tool_levels: dict[str, str] = field(default_factory=dict)
    injection_patterns_count: int = 0
    injection_block_enabled: bool = False
    rag_write_policy_enabled: bool = False
    rag_drift_detection_enabled: bool = False

    # Files scanned
    python_files: list[str] = field(default_factory=list)
    config_files: list[str] = field(default_factory=list)
    requirement_files: list[str] = field(default_factory=list)

    @property
    def frameworks_detected(self) -> list[str]:
        found = []
        if self.has_langchain:
            found.append("LangChain")
        if self.has_crewai:
            found.append("CrewAI")
        if self.has_openai_agents:
            found.append("OpenAI Agents")
        if self.has_autogen:
            found.append("AutoGen")
        if self.has_typescript:
            found.append("TypeScript")
        if self.has_gateway:
            found.append("Gateway")
        if self.has_rag_trust:
            found.append("RAG Trust")
        return found

    @property
    def air_components_detected(self) -> list[str]:
        found = []
        if self.has_audit_ledger:
            found.append("AuditLedger")
        if self.has_data_vault:
            found.append("DataVault")
        if self.has_consent_gate:
            found.append("ConsentGate")
        if self.has_injection_detector:
            found.append("InjectionDetector")
        if self.has_trust_handler:
            found.append("TrustHandler")
        if self.has_trust_config:
            found.append("TrustConfig")
        if self.has_provenance_tracker:
            found.append("ProvenanceTracker")
        if self.has_write_gate:
            found.append("WriteGate")
        if self.has_drift_detector:
            found.append("DriftDetector")
        return found


# Patterns to detect in Python source files
IMPORT_PATTERNS = {
    # AIR trust packages
    "air_langchain_trust": "has_langchain",
    "air_crewai_trust": "has_crewai",
    "air_openai_agents_trust": "has_openai_agents",
    "air_autogen_trust": "has_autogen",
    "air_rag_trust": "has_rag_trust",
    # Framework imports
    "langchain": "has_langchain",
    "crewai": "has_crewai",
    "autogen": "has_autogen",
    "openai.agents": "has_openai_agents",
}

COMPONENT_PATTERNS = {
    r"AuditLedger": "has_audit_ledger",
    r"DataVault": "has_data_vault",
    r"ConsentGate": "has_consent_gate",
    r"InjectionDetector": "has_injection_detector",
    r"AirTrustCallbackHandler|AirTrustHook|activate_trust": "has_trust_handler",
    r"AirTrustConfig": "has_trust_config",
    r"ProvenanceTracker": "has_provenance_tracker",
    r"WriteGate|WritePolicy": "has_write_gate",
    r"DriftDetector|DriftConfig": "has_drift_detector",
    r"AirRagTrust": "has_rag_trust",
}

CONFIG_PATTERNS = {
    r"hmac|secret.*key|audit_secret": "audit_hmac_enabled",
    r"block.*=.*True|block_mode|injection.*block": "injection_block_enabled",
    r"WritePolicy|allowed_sources|blocked_sources|write.*gate": "rag_write_policy_enabled",
    r"DriftConfig|drift.*detect|baseline_window|untrusted_ratio": "rag_drift_detection_enabled",
}


class ProjectScanner:
    """Scans a project directory for AIR Blackbox components."""

    def __init__(self, project_path: str):
        self.project_path = Path(project_path).resolve()
        if not self.project_path.exists():
            raise FileNotFoundError(f"Project path not found: {self.project_path}")

    def scan(self) -> ScanResult:
        """Scan the project and return findings."""
        result = ScanResult()

        # Collect files
        result.python_files = self._find_files("*.py")
        result.config_files = self._find_files("*.yaml") + self._find_files("*.yml") + self._find_files("*.toml")
        result.requirement_files = self._find_files("requirements*.txt") + self._find_files("pyproject.toml")

        # Scan Python files for imports and components
        for py_file in result.python_files:
            content = self._read_file(py_file)
            if content is None:
                continue
            self._scan_imports(content, result)
            self._scan_components(content, result)
            self._scan_config(content, result)

        # Scan requirement files for AIR packages
        for req_file in result.requirement_files:
            content = self._read_file(req_file)
            if content is None:
                continue
            self._scan_requirements(content, result)

        # Scan YAML/TOML config files
        for cfg_file in result.config_files:
            content = self._read_file(cfg_file)
            if content is None:
                continue
            self._scan_config(content, result)
            self._scan_yaml_config(content, result)

        # Check for gateway (Docker)
        for dockerfile in self._find_files("Dockerfile") + self._find_files("docker-compose*"):
            content = self._read_file(dockerfile)
            if content and "airblackbox/gateway" in content:
                result.has_gateway = True

        # Check for TypeScript trust package
        for pkg_file in self._find_files("package.json"):
            content = self._read_file(pkg_file)
            if content and "openclaw-air-trust" in content:
                result.has_typescript = True

        return result

    def _find_files(self, pattern: str) -> list[str]:
        """Find files matching a glob pattern, excluding common noise dirs."""
        exclude = {".git", "node_modules", "__pycache__", ".venv", "venv", ".tox", "dist", "build", ".egg-info"}
        matches = []
        for path in self.project_path.rglob(pattern):
            if any(part in exclude for part in path.parts):
                continue
            matches.append(str(path))
        return matches

    def _read_file(self, filepath: str) -> Optional[str]:
        """Read file contents, return None on error."""
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                return f.read()
        except (OSError, PermissionError):
            return None

    def _scan_imports(self, content: str, result: ScanResult) -> None:
        """Detect framework and AIR package imports."""
        for pattern, attr in IMPORT_PATTERNS.items():
            if re.search(rf"(?:import|from)\s+{re.escape(pattern)}", content):
                setattr(result, attr, True)

    def _scan_components(self, content: str, result: ScanResult) -> None:
        """Detect AIR Blackbox component usage."""
        for pattern, attr in COMPONENT_PATTERNS.items():
            if re.search(pattern, content):
                setattr(result, attr, True)

    def _scan_config(self, content: str, result: ScanResult) -> None:
        """Detect configuration patterns."""
        for pattern, attr in CONFIG_PATTERNS.items():
            if re.search(pattern, content, re.IGNORECASE):
                setattr(result, attr, True)

    def _scan_requirements(self, content: str, result: ScanResult) -> None:
        """Scan requirements files for AIR packages."""
        if "air-langchain-trust" in content or "air_langchain_trust" in content:
            result.has_langchain = True
        if "air-crewai-trust" in content or "air_crewai_trust" in content:
            result.has_crewai = True
        if "air-openai-agents-trust" in content or "air_openai_agents_trust" in content:
            result.has_openai_agents = True
        if "air-autogen-trust" in content or "air_autogen_trust" in content:
            result.has_autogen = True
        if "openclaw-air-trust" in content:
            result.has_typescript = True
        if "air-rag-trust" in content or "air_rag_trust" in content:
            result.has_rag_trust = True

    def _scan_yaml_config(self, content: str, result: ScanResult) -> None:
        """Extract config details from YAML/TOML files."""
        # Detect vault patterns
        vault_patterns = re.findall(r"(?:patterns?|categories?):\s*\[?([^\]\n]+)", content, re.IGNORECASE)
        for match in vault_patterns:
            items = [s.strip().strip("'\"") for s in match.split(",")]
            result.vault_patterns.extend(items)

        # Detect consent mode
        mode_match = re.search(r"(?:consent_mode|mode)\s*[:=]\s*[\"']?(\w+)", content, re.IGNORECASE)
        if mode_match:
            result.consent_mode = mode_match.group(1)

        # Detect injection pattern count
        inj_patterns = re.findall(r"(?:injection|pattern).*?:", content, re.IGNORECASE)
        result.injection_patterns_count = max(result.injection_patterns_count, len(inj_patterns))