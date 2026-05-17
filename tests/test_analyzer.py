import unittest

from api_risk_analyzer.report import build_report, render_markdown, render_sarif
from api_risk_analyzer.parser import validate_endpoints



class AnalyzerTest(unittest.TestCase):
    def test_validate_requires_a_list(self):
        with self.assertRaisesRegex(ValueError, "list of endpoints"):
            validate_endpoints({"path": "/api/users"})

    def test_validate_requires_method_and_path(self):
        with self.assertRaisesRegex(ValueError, "missing a valid method"):
            validate_endpoints([{"path": "/api/users"}])

        with self.assertRaisesRegex(ValueError, "missing a valid path"):
            validate_endpoints([{"method": "GET"}])

    def test_build_report_counts_severity(self):
        report = build_report(
            endpoints=[{"method": "GET", "path": "/api/users"}],
            findings=[
                {"severity": "critical"},
                {"severity": "high"},
                {"severity": "high"},
            ],
        )

        self.assertEqual(report["total_endpoints"], 1)
        self.assertEqual(report["summary"]["total_findings"], 3)
        self.assertEqual(report["summary"]["critical"], 1)
        self.assertEqual(report["summary"]["high"], 2)

    def test_build_report_includes_endpoint_scores(self):
        endpoints = [
            {"method": "GET", "path": "/api/public"},
            {"method": "POST", "path": "/api/admin"},
        ]
        findings = [
            {
                "method": "POST",
                "path": "/api/admin",
                "severity": "critical",
                "rule_id": "API5-001",
            }
        ]
        report = build_report(endpoints, findings)
        self.assertIn("endpoint_scores", report)
        self.assertEqual(len(report["endpoint_scores"]), 2)
        self.assertEqual(report["endpoint_scores"][0], {"method": "GET", "path": "/api/public", "score": "low"})
        self.assertEqual(report["endpoint_scores"][1], {"method": "POST", "path": "/api/admin", "score": "critical"})


    def test_build_report_sorts_findings_by_risk(self):
        report = build_report(
            endpoints=[],
            findings=[
                {
                    "severity": "medium",
                    "path": "/api/profile",
                    "method": "GET",
                    "rule_id": "DATA-001",
                },
                {
                    "severity": "critical",
                    "path": "/api/users/{id}",
                    "method": "GET",
                    "rule_id": "API1-001",
                },
                {
                    "severity": "high",
                    "path": "/api/auth/login",
                    "method": "POST",
                    "rule_id": "AUTH-002",
                },
                {"severity": "low", "path": "/api/status", "method": "GET", "rule_id": "INFO-001"},
            ],
        )

        self.assertEqual(
            [finding["severity"] for finding in report["findings"]],
            ["critical", "high", "medium", "low"],
        )

    def test_render_markdown_contains_findings_table(self):
        report = {
            "generated_at": "2026-05-08T16:45:00Z",
            "total_endpoints": 1,
            "summary": {"total_findings": 1},
            "findings": [
                {
                    "severity": "high",
                    "rule_id": "AUTH-001",
                    "method": "GET",
                    "path": "/api/private",
                    "description": "Missing auth.",
                }
            ],
        }

        output = render_markdown(report)

        self.assertIn("| high | AUTH-001 | GET | `/api/private` | Missing auth. |", output)

    def test_render_markdown_escapes_pipes(self):
        report = {
            "generated_at": "2026-05-08T16:45:00Z",
            "total_endpoints": 1,
            "summary": {"total_findings": 1},
            "findings": [
                {
                    "severity": "high",
                    "rule_id": "AUTH|001",
                    "method": "G|ET",
                    "path": "/api/private|test",
                    "description": "Missing | auth",
                    "evidence": "no | evidence",
                }
            ],
        }
        output = render_markdown(report)
        self.assertIn(
            (
                r"| high | AUTH\|001 | G\|ET | `/api/private\|test` | "
                r"Missing \| auth | no \| evidence |"
            ),
            output,
        )

    def test_render_sarif_contains_rules_and_results(self):
        report = build_report(
            endpoints=[],
            findings=[
                {
                    "severity": "critical",
                    "rule_id": "API1-001",
                    "method": "GET",
                    "path": "/api/users/{id}",
                    "description": "Object authorization is missing.",
                    "recommendation": "Check object ownership before returning data.",
                    "category": "broken-object-level-authorization",
                    "evidence": "object_authorization is false",
                }
            ],
        )

        output = render_sarif(report, "examples/sample_api.json")
        run = output["runs"][0]
        result = run["results"][0]

        self.assertEqual(output["version"], "2.1.0")
        self.assertEqual(run["tool"]["driver"]["name"], "api-risk-analyzer")
        self.assertEqual(run["tool"]["driver"]["rules"][0]["id"], "API1-001")
        self.assertEqual(result["ruleId"], "API1-001")
        self.assertEqual(result["level"], "error")
        self.assertEqual(
            result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
            "examples/sample_api.json",
        )
        self.assertIn("primaryLocationLineHash", result["partialFingerprints"])

    def test_render_sarif_does_not_leak_absolute_input_path(self):
        report = build_report(
            endpoints=[],
            findings=[
                {
                    "severity": "high",
                    "rule_id": "AUTH-001",
                    "method": "GET",
                    "path": "/api/private",
                    "description": "Authentication is missing.",
                }
            ],
        )

        output = render_sarif(report, r"C:\work\sample_api.json")
        uri = output["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
        uri = uri["artifactLocation"]["uri"]

        self.assertEqual(uri, "sample_api.json")
        self.assertNotIn("C:", uri)
        self.assertNotIn("work", uri)




if __name__ == "__main__":
    unittest.main()
