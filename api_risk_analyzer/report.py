import json
import hashlib
from datetime import datetime, timezone
from pathlib import Path, PureWindowsPath

from api_risk_analyzer.rules import score_endpoint

SEVERITY_ORDER = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
}

SARIF_LEVELS = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
}

SARIF_SECURITY_SEVERITY = {
    "critical": "9.0",
    "high": "7.0",
    "medium": "5.0",
    "low": "3.0",
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


def _safe_artifact_uri(path):
    if not path:
        return "api-routes.json"

    path_value = str(path)
    windows_path = PureWindowsPath(path_value)
    if windows_path.drive:
        return windows_path.name

    input_path = Path(path_value)
    if input_path.is_absolute():
        return input_path.name

    return input_path.as_posix()


def _sarif_level(severity):
    return SARIF_LEVELS.get(severity, "warning")


def _sarif_security_severity(severity):
    return SARIF_SECURITY_SEVERITY.get(severity, "5.0")


def _finding_fingerprint(finding):
    parts = [
        finding.get("rule_id", ""),
        finding.get("method", ""),
        finding.get("path", ""),
        finding.get("evidence", ""),
    ]
    value = "|".join(str(part) for part in parts)
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _sarif_rules(findings):
    rules = []
    seen = set()

    for finding in findings:
        rule_id = finding.get("rule_id", "UNKNOWN")
        if rule_id in seen:
            continue

        severity = finding.get("severity", "medium")
        rule = {
            "id": rule_id,
            "name": finding.get("category", rule_id),
            "shortDescription": {
                "text": finding.get("description", rule_id),
            },
            "defaultConfiguration": {
                "level": _sarif_level(severity),
            },
            "properties": {
                "security-severity": _sarif_security_severity(severity),
                "tags": [
                    "api-security",
                    finding.get("category", "api-risk"),
                ],
            },
        }

        recommendation = finding.get("recommendation")
        if recommendation:
            rule["fullDescription"] = {"text": recommendation}

        rules.append(rule)
        seen.add(rule_id)

    return rules


def compute_endpoint_scores(endpoints, findings):
    findings_by_index = {}
    has_index = False
    if findings:
        for f in findings:
            idx = f.get("endpoint_index")
            if idx is not None:
                has_index = True
                findings_by_index.setdefault(idx, []).append(f)

    scores = []
    for index, ep in enumerate(endpoints):
        method = ep.get("method", "").upper()
        path = ep.get("path", "")
        if has_index:
            ep_findings = findings_by_index.get(index, [])
        else:
            ep_findings = [
                f for f in (findings or [])
                if f.get("method", "").upper() == method and f.get("path", "") == path
            ]
        scores.append({
            "method": method,
            "path": path,
            "score": score_endpoint(ep, endpoint_findings=ep_findings),
        })
    return scores






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
        "generated_at": (
            datetime.now(timezone.utc)
            .replace(microsecond=0)
            .isoformat()
            .replace("+00:00", "Z")
        ),
        "total_endpoints": len(endpoints),
        "summary": summary,
        "endpoint_scores": compute_endpoint_scores(endpoints, findings),
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
    ]

    if report.get("endpoint_scores"):
        lines.extend([
            "## Endpoint Risk Overview",
            "",
            "| Method | Path | Risk Score |",
            "|---|---|---|",
        ])
        for ep in report["endpoint_scores"]:
            method = _escape_markdown_cell(ep.get("method", "UNKNOWN"))
            path = _escape_markdown_cell(ep.get("path", "UNKNOWN"))
            score = _escape_markdown_cell(ep.get("score", "low"))
            lines.append(f"| {method} | `{path}` | {score} |")
        lines.append("")

    lines.extend([
        "## Findings",
        "",
        "| Severity | Rule | Method | Path | Description | Evidence |",
        "|---|---|---|---|---|---|",
    ])

    for finding in report.get("findings", []):
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


def render_sarif(report, source_path=None):
    artifact_uri = _safe_artifact_uri(source_path)
    findings = report.get("findings", [])

    results = []
    for finding in findings:
        method = finding.get("method", "UNKNOWN")
        path = finding.get("path", "UNKNOWN")
        description = finding.get("description", "API risk found.")
        severity = finding.get("severity", "medium")

        results.append({
            "ruleId": finding.get("rule_id", "UNKNOWN"),
            "level": _sarif_level(severity),
            "message": {
                "text": f"{description} ({method} {path})",
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": artifact_uri,
                        },
                        "region": {
                            "startLine": 1,
                        },
                    },
                },
            ],
            "partialFingerprints": {
                "primaryLocationLineHash": _finding_fingerprint(finding),
            },
        })

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "api-risk-analyzer",
                        "informationUri": "https://owasp.org/API-Security/",
                        "rules": _sarif_rules(findings),
                    },
                },
                "results": results,
            },
        ],
    }


def write_markdown(report, path):
    output_path = Path(path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8", newline="\n") as file:
        file.write(render_markdown(report))
    print(f"report saved: {output_path}")


def write_sarif(report, path, source_path=None):
    output_path = Path(path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8", newline="\n") as file:
        json.dump(render_sarif(report, source_path), file, indent=2, ensure_ascii=False)
        file.write("\n")
    print(f"report saved: {output_path}")
