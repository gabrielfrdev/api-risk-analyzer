import json
from datetime import datetime, timezone
from pathlib import Path

SEVERITY_ORDER = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
}


def _escape_markdown_cell(text):
    return str(text).replace("|", "\\|")


def _finding_sort_key(finding):
    return (
        SEVERITY_ORDER.get(finding.get("severity"), len(SEVERITY_ORDER)),
        finding.get("path", ""),
        finding.get("method", ""),
        finding.get("rule_id", ""),
    )


def build_report(endpoints, findings):
    summary = {
        "total_findings": len(findings),
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
    }

    for finding in findings:
        severity = finding.get("severity", "low")
        if severity in summary:
            summary[severity] += 1

    return {
        "generated_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "total_endpoints": len(endpoints),
        "summary": summary,
        "findings": sorted(findings, key=_finding_sort_key),
    }


def write_json(report, path):
    output_path = Path(path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8", newline="\n") as file:
        json.dump(report, file, indent=2, ensure_ascii=False)
        file.write("\n")
    print(f"report saved: {output_path}")


def render_markdown(report):
    lines = [
        "# API Risk Report",
        "",
        f"Generated at: `{report['generated_at']}`",
        f"Endpoints checked: `{report['total_endpoints']}`",
        f"Findings: `{report['summary']['total_findings']}`",
        "",
        "| Severity | Rule | Method | Path | Description | Evidence |",
        "|---|---|---|---|---|---|",
    ]

    for finding in report["findings"]:
        severity = _escape_markdown_cell(finding.get("severity", "UNKNOWN"))
        rule_id = _escape_markdown_cell(finding.get("rule_id", "UNKNOWN"))
        method = _escape_markdown_cell(finding.get("method", "UNKNOWN"))
        path = _escape_markdown_cell(finding.get("path", "UNKNOWN"))
        description = _escape_markdown_cell(finding.get("description", ""))
        evidence = _escape_markdown_cell(finding.get("evidence") or "-")

        lines.append(
            f"| {severity} | {rule_id} | {method} | `{path}` | {description} | {evidence} |"
        )

    return "\n".join(lines) + "\n"


def write_markdown(report, path):
    output_path = Path(path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8", newline="\n") as file:
        file.write(render_markdown(report))
    print(f"report saved: {output_path}")
