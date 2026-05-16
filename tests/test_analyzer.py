import unittest

from api_risk_analyzer.report import build_report, render_markdown
from api_risk_analyzer.parser import validate_endpoints

from api_risk_analyzer.rules import (
    check_admin_without_role,
    check_unsigned_webhook,
    check_login_without_rate_limit,
)
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

    def test_build_report_sorts_findings_by_risk(self):
        report = build_report(
            endpoints=[],
            findings=[
                {"severity": "medium", "path": "/api/profile", "method": "GET", "rule_id": "DATA-001"},
                {"severity": "critical", "path": "/api/users/{id}", "method": "GET", "rule_id": "API1-001"},
                {"severity": "high", "path": "/api/auth/login", "method": "POST", "rule_id": "AUTH-002"},
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
                    "evidence": "no | evidence"
                }
            ],
        }
        output = render_markdown(report)
        self.assertIn(r"| high | AUTH\|001 | G\|ET | `/api/private\|test` | Missing \| auth | no \| evidence |", output)

    def test_segment_based_matching_avoids_false_positives(self):
        endpoints = [
            {"method": "GET", "path": "/api/administration"},
            {"method": "POST", "path": "/api/webhook_handler"},
            {"method": "POST", "path": "/api/login_history"}
        ]
        
        # admin without role
        self.assertEqual(len(check_admin_without_role(endpoints)), 0)
        
        # webhook without signature
        self.assertEqual(len(check_unsigned_webhook(endpoints)), 0)
        
        # login without rate limit
        self.assertEqual(len(check_login_without_rate_limit(endpoints)), 0)

        endpoints_positive = [
            {"method": "GET", "path": "/api/admin"},
            {"method": "POST", "path": "/api/webhook/github"},
            {"method": "POST", "path": "/api/auth/login"}
        ]
        
        self.assertEqual(len(check_admin_without_role(endpoints_positive)), 1)
        self.assertEqual(len(check_unsigned_webhook(endpoints_positive)), 1)
        self.assertEqual(len(check_login_without_rate_limit(endpoints_positive)), 1)


if __name__ == "__main__":
    unittest.main()
