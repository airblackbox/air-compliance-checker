# EU AI Act Compliance Scanner

**Tool-agnostic** compliance scanner for Python AI projects. Checks whether your project follows EU AI Act technical requirements — regardless of what libraries you use.

## What it checks

The scanner evaluates your project against 6 EU AI Act articles that apply to high-risk AI systems:

| Article | What it looks for |
|---------|------------------|
| **Art. 9** — Risk Management | Risk classification, access control, risk decision logging |
| **Art. 10** — Data Governance | Input validation (Pydantic, marshmallow, etc.), PII handling, data schemas |
| **Art. 11** — Technical Docs | Logging (structlog, loguru, etc.), docstrings, type hints |
| **Art. 12** — Record-Keeping | Structured logging, audit trails, timestamps, log integrity |
| **Art. 14** — Human Oversight | Review flows, override/kill switch, notifications |
| **Art. 15** — Robustness | Input sanitization, error handling, tests, rate limiting |

## Tool-agnostic

This scanner does **not** require any specific library. A project using standard Python tools passes just fine:

- **Logging**: `logging`, `structlog`, `loguru` — any works
- **Validation**: `pydantic`, `marshmallow`, `cerberus`, `jsonschema`, `dataclasses` — any works
- **Testing**: `pytest`, `unittest` — any works
- **PII handling**: `presidio`, `scrubadub`, regex-based redaction — any works
- **Error handling**: standard `try/except` — works
- **Rate limiting**: `slowapi`, `flask-limiter`, custom implementations — any works

## Install

```bash
pip install air-compliance
```

## Usage

```bash
# Scan current directory
air-compliance .

# Verbose output with evidence
air-compliance . --verbose

# JSON output (for CI pipelines)
air-compliance . --json

# Fail CI if any check fails
air-compliance . --strict
```

### Python API

```python
from air_compliance import ProjectScanner
from air_compliance.checkers import ALL_CHECKERS
from air_compliance.models import ComplianceReport

scanner = ProjectScanner("/path/to/project")
scan_result = scanner.scan()

report = ComplianceReport(project_path="/path/to/project")
for checker in ALL_CHECKERS:
    report.articles.append(checker(scan_result))

print(f"Coverage: {report.coverage_pct:.0f}%")
print(f"Pass: {report.total_pass}, Fail: {report.total_fail}")
```

### GitHub Actions

```yaml
- name: EU AI Act Compliance Check
  run: |
    pip install air-compliance
    air-compliance . --strict
```

## Example output

```
============================================================
  EU AI Act Compliance Scanner
============================================================

  Project: /home/user/my-ai-project
  Frameworks: LangChain, FastAPI

  Overall: PASS  |  Coverage: 85%  |  17 pass / 3 warn / 2 fail

  Article 9 — Risk Management System  [PASS]

    ● Risk levels defined for AI operations
    ● Access control on AI-driven actions
    ● Risk decisions logged for review

  Article 10 — Data and Data Governance  [PASS]

    ● Input data validated with schemas or type checking
    ● Personal/sensitive data identified and handled
    ● Data structures defined with typed schemas
    ○ Data sources tracked with provenance information
      → Track data sources and lineage (e.g., source URLs, document IDs, content hashes)

  This scanner is tool-agnostic — use any libraries you prefer.
```

## v1.0.0 — Tool-agnostic rewrite

Previous versions checked for specific packages. v1.0.0 is a complete rewrite that checks for **real compliance patterns** — logging, validation, testing, error handling, documentation — using any tools you prefer. A project using Pydantic + structlog + pytest passes just as well as one using any other stack.

## EU AI Act timeline

- **August 2, 2026**: High-risk AI system requirements become enforceable
- **Articles 9-15**: Technical requirements for high-risk AI systems

## Contributing

Issues and PRs welcome. This is an open-source project under the Apache 2.0 license.

## License

Apache-2.0
