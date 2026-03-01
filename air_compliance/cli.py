"""CLI interface for the EU AI Act Compliance Scanner."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from air_compliance.models import ComplianceReport, Status
from air_compliance.scanner import ProjectScanner
from air_compliance.checkers import ALL_CHECKERS


# ANSI color codes
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"

STATUS_ICONS = {
    Status.PASS: f"{GREEN}PASS{RESET}",
    Status.FAIL: f"{RED}FAIL{RESET}",
    Status.WARN: f"{YELLOW}WARN{RESET}",
    Status.SKIP: f"{DIM}SKIP{RESET}",
}

STATUS_DOTS = {
    Status.PASS: f"{GREEN}●{RESET}",
    Status.FAIL: f"{RED}●{RESET}",
    Status.WARN: f"{YELLOW}●{RESET}",
    Status.SKIP: f"{DIM}○{RESET}",
}


def run_scan(project_path: str) -> ComplianceReport:
    """Run the full compliance scan and return a report."""
    scanner = ProjectScanner(project_path)
    scan_result = scanner.scan()

    report = ComplianceReport(
        project_path=project_path,
        frameworks_detected=scan_result.frameworks_detected,
    )

    for checker in ALL_CHECKERS:
        try:
            article_result = checker(scan_result)
            report.articles.append(article_result)
        except Exception as e:
            report.scan_errors.append(f"{checker.__name__}: {e}")

    return report


def print_report(report: ComplianceReport, verbose: bool = False) -> None:
    """Print a formatted compliance report to stdout."""
    print()
    print(f"{BOLD}{'=' * 60}{RESET}")
    print(f"{BOLD}  EU AI Act Compliance Scanner{RESET}")
    print(f"{BOLD}{'=' * 60}{RESET}")
    print()
    print(f"  Project: {report.project_path}")

    if report.frameworks_detected:
        print(f"  Frameworks: {', '.join(report.frameworks_detected)}")
    else:
        print(f"  Frameworks: {DIM}None detected{RESET}")

    # Overall status bar
    overall = report.overall_status
    overall_icon = STATUS_ICONS[overall]
    print()
    print(f"  Overall: {overall_icon}  |  Coverage: {report.coverage_pct:.0f}%  |  {report.total_pass} pass / {report.total_warn} warn / {report.total_fail} fail")
    print()

    # Per-article results
    for article in report.articles:
        status_icon = STATUS_ICONS[article.status]
        print(f"{BOLD}  {article.article} — {article.title}{RESET}  [{status_icon}]")
        print()

        for check in article.checks:
            dot = STATUS_DOTS[check.status]
            print(f"    {dot} {check.description}")

            if verbose:
                print(f"      {DIM}Requirement: {check.requirement}{RESET}")
                if check.evidence:
                    print(f"      {DIM}Evidence: {check.evidence}{RESET}")

            if check.status in (Status.FAIL, Status.WARN) and check.recommendation:
                marker = f"{RED}→{RESET}" if check.status == Status.FAIL else f"{YELLOW}→{RESET}"
                print(f"      {marker} {check.recommendation}")

        print()

    # Summary
    print(f"{BOLD}{'─' * 60}{RESET}")
    if report.overall_status == Status.PASS:
        print(f"  {GREEN}{BOLD}All compliance checks passed.{RESET}")
        print(f"  Your project covers EU AI Act Articles 9, 10, 11, 12, 14, 15.")
    elif report.overall_status == Status.WARN:
        print(f"  {YELLOW}{BOLD}Compliance checks passed with warnings.{RESET}")
        print(f"  {report.total_warn} items need attention for full compliance.")
    else:
        print(f"  {RED}{BOLD}{report.total_fail} compliance gaps detected.{RESET}")
        print(f"  Address the FAIL items above to improve EU AI Act readiness.")
        print(f"  Run with --verbose for detailed requirements and evidence.")

    print()
    print(f"  {DIM}EU AI Act high-risk enforcement: August 2, 2026{RESET}")
    print(f"  {DIM}This scanner is tool-agnostic — use any libraries you prefer.{RESET}")
    print()

    if report.scan_errors:
        print(f"  {RED}Scan errors:{RESET}")
        for err in report.scan_errors:
            print(f"    - {err}")
        print()


def print_json(report: ComplianceReport) -> None:
    """Print the report as JSON."""
    data = {
        "project_path": report.project_path,
        "overall_status": report.overall_status.value,
        "coverage_pct": report.coverage_pct,
        "frameworks_detected": report.frameworks_detected,
        "summary": {
            "total": report.total_checks,
            "pass": report.total_pass,
            "warn": report.total_warn,
            "fail": report.total_fail,
        },
        "articles": [],
    }

    for article in report.articles:
        art_data = {
            "article": article.article,
            "title": article.title,
            "status": article.status.value,
            "checks": [],
        }
        for check in article.checks:
            art_data["checks"].append({
                "name": check.name,
                "status": check.status.value,
                "description": check.description,
                "requirement": check.requirement,
                "recommendation": check.recommendation,
                "evidence": check.evidence,
            })
        data["articles"].append(art_data)

    print(json.dumps(data, indent=2))


def main() -> int:
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        prog="air-compliance",
        description="EU AI Act Compliance Scanner — check your Python AI project for compliance gaps (tool-agnostic)",
    )
    parser.add_argument(
        "path",
        nargs="?",
        default=".",
        help="Path to the project directory to scan (default: current directory)",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Show detailed requirements and evidence for each check",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        dest="json_output",
        help="Output results as JSON",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Exit with code 1 if any check fails (useful for CI)",
    )
    parser.add_argument(
        "--version",
        action="version",
        version="air-compliance 1.0.0",
    )

    args = parser.parse_args()

    try:
        path = str(Path(args.path).resolve())
        report = run_scan(path)
    except FileNotFoundError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Scan error: {e}", file=sys.stderr)
        return 1

    if args.json_output:
        print_json(report)
    else:
        print_report(report, verbose=args.verbose)

    if args.strict and report.overall_status == Status.FAIL:
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
