import unittest

from api_risk_analyzer.report import build_report, render_markdown
from api_risk_analyzer.parser import validate_endpoints


class AnalyzerTest(unittest.TestCase):
    def test_validate_requires_a_list(self):
        with self.assertRaisesRegex(ValueError, "list of endpoints"):
            validate_endpoints({"path": "/api/users"})

    def test_validate_requires_method_and_path(self):
        with self.assertRaisesRegex(ValueError, "missing method"):
            validate_endpoints([{"path": "/api/users"}])

        with self.assertRaisesRegex(ValueError, "missing path"):
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


if __name__ == "__main__":
    unittest.main()
