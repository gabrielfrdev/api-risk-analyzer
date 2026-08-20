import argparse
from importlib.metadata import PackageNotFoundError, version

from api_risk_analyzer.report import build_report, write_json, write_markdown, write_sarif
from api_risk_analyzer.rules import run_rules
from api_risk_analyzer.parser import load_api


def _package_version():
    try:
        return version("api-risk-analyzer")
    except PackageNotFoundError:
        return "0.0.0-dev"


def main():
    parser = argparse.ArgumentParser(
        description="Analyze API endpoint metadata for common security risks."
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {_package_version()}",
    )
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", default=None)
    parser.add_argument("--format", choices=["json", "markdown", "sarif"], default="json")
    parser.add_argument(
        "--fail-on",
        choices=["low", "medium", "high", "critical"],
        help="Exit with code 1 if findings meet or exceed this severity"
    )
    args = parser.parse_args()

    if args.output is None:
        extension = {
            "json": "json",
            "markdown": "md",
            "sarif": "sarif",
        }[args.format]
        args.output = f"reports/generated-report.{extension}"

    try:
        endpoints = load_api(args.input)
    except ValueError as error:
        print(f"error: {error}")
        return 1

    print(f"loaded endpoints: {len(endpoints)}")

    findings = run_rules(endpoints)

    if not findings:
        print("findings: 0")
    else:
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for f in findings:
            counts[f["severity"]] = counts.get(f["severity"], 0) + 1

        summary_parts = [
            f"{level}: {counts[level]}"
            for level in ["critical", "high", "medium", "low"]
            if counts[level] > 0
        ]
        print(f"findings: {len(findings)} ({', '.join(summary_parts)})")

    report = build_report(endpoints, findings)
    if args.format == "sarif":
        write_sarif(report, args.output, args.input)
    elif args.format == "markdown":
        write_markdown(report, args.output)
    else:
        write_json(report, args.output)

    if args.fail_on:
        severity_levels = {"low": 1, "medium": 2, "high": 3, "critical": 4}
        threshold = severity_levels[args.fail_on]
        for f in findings:
            if severity_levels.get(f["severity"], 0) >= threshold:
                print(f"Failed: found {f['severity']} severity issue (limit was {args.fail_on})")
                return 1

    return 0
