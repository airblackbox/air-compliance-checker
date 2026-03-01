# air-compliance

**EU AI Act compliance checker for AI agent projects.** Scans your codebase for AIR Blackbox components and reports which EU AI Act articles you're covered on — and which have gaps.

```
$ air-compliance /path/to/my-agent-project

============================================================
  AIR Blackbox — EU AI Act Compliance Report
============================================================

  Project: /path/to/my-agent-project
  Frameworks: LangChain

  Overall: PASS  |  Coverage: 100%  |  22 pass / 0 warn / 0 fail

  Article 9 — Risk Management System  [PASS]

    ● Tool calls classified by risk level
    ● Risk levels configurable per tool
    ● Risk-based blocking policy enforced at runtime
    ● Risk decisions logged to audit trail

  Article 10 — Data and Data Governance  [PASS]
  ...

  Article 12 — Record-Keeping  [PASS]

    ● Events automatically recorded over system lifetime
    ● Consent decisions logged with tool name, risk level, allow/deny
    ● Injection detection results logged with pattern and match
    ● HMAC-SHA256 chained logs — mathematically verifiable integrity

  EU AI Act high-risk enforcement: August 2, 2026
```

## Install

```bash
pip install air-compliance
```

## Usage

```bash
# Scan current directory
air-compliance

# Scan a specific project
air-compliance /path/to/project

# Verbose output (shows requirements and evidence)
air-compliance --verbose

# JSON output (for CI pipelines)
air-compliance --json

# Strict mode (exit code 1 on any failure — use in CI)
air-compliance --strict
```

## What It Checks

The checker scans your project for AIR Blackbox components and maps them to 6 EU AI Act articles:

| Article | Requirement | What It Looks For |
|---|---|---|
| **Art. 9** | Risk Management | ConsentGate, risk levels, blocking policies, audit trail |
| **Art. 10** | Data Governance | DataVault, PII patterns, prompt logging |
| **Art. 11** | Technical Documentation | AuditLedger, call graph capture, HMAC integrity |
| **Art. 12** | Record-Keeping | Auto recording, consent logging, injection logging, tamper-evident chain |
| **Art. 14** | Human Oversight | Audit trail, consent gate, intervention capability, interpretable output |
| **Art. 15** | Robustness & Security | InjectionDetector, blocking, defense-in-depth layers, configurable security |

## CI Integration

Add to your CI pipeline to block deploys that aren't compliant:

```yaml
# .github/workflows/compliance.yml
name: EU AI Act Compliance
on: [push, pull_request]

jobs:
  compliance:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: pip install air-compliance
      - run: air-compliance --strict
```

## JSON Output

```bash
air-compliance --json | jq '.articles[] | {article, status}'
```

```json
{"article": "Article 9", "status": "pass"}
{"article": "Article 10", "status": "pass"}
{"article": "Article 11", "status": "warn"}
{"article": "Article 12", "status": "fail"}
{"article": "Article 14", "status": "pass"}
{"article": "Article 15", "status": "pass"}
```

## AIR Blackbox Ecosystem

| Package | Framework | Install |
|---|---|---|
| `air-langchain-trust` | LangChain / LangGraph | `pip install air-langchain-trust` |
| `air-crewai-trust` | CrewAI | `pip install air-crewai-trust` |
| `openclaw-air-trust` | TypeScript / Node.js | `npm install openclaw-air-trust` |
| Gateway | Any HTTP agent | `docker pull ghcr.io/airblackbox/gateway:main` |
| **`air-compliance`** | **Compliance checker** | **`pip install air-compliance`** |

## License

Apache-2.0