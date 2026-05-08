import unittest

from api_risk_analyzer.rules import run_rules, score_endpoint


class RulesTest(unittest.TestCase):
    def test_public_endpoint_without_auth_is_allowed(self):
        findings = run_rules([
            {
                "method": "GET",
                "path": "/api/products",
                "public": True,
                "auth_required": False,
                "rate_limit": True,
                "signature_required": False,
                "response_sensitive_fields": [],
            }
        ])

        self.assertEqual(findings, [])

    def test_private_endpoint_without_auth_is_reported(self):
        findings = run_rules([
            {
                "method": "GET",
                "path": "/api/billing/export",
                "public": False,
                "auth_required": False,
                "response_sensitive_fields": [],
            }
        ])

        self.assertEqual(findings[0]["rule_id"], "AUTH-001")
        self.assertEqual(findings[0]["severity"], "high")

    def test_object_id_patterns_are_reported(self):
        findings = run_rules([
            {
                "method": "GET",
                "path": "/api/users/:user_id",
                "auth_required": True,
                "object_authorization": False,
                "response_sensitive_fields": [],
            }
        ])

        self.assertEqual(findings[0]["rule_id"], "API1-001")

    def test_object_id_pattern_ignores_slugs(self):
        findings = run_rules([
            {
                "method": "GET",
                "path": "/api/products/{slug}",
                "auth_required": True,
                "object_authorization": False,
                "response_sensitive_fields": [],
            }
        ])

        self.assertEqual(findings, [])

    def test_sample_style_endpoint_gets_expected_score(self):
        endpoint = {
            "method": "DELETE",
            "path": "/admin/users/{id}",
            "auth_required": True,
            "object_authorization": False,
            "role_required": None,
            "response_sensitive_fields": [],
        }

        self.assertEqual(score_endpoint(endpoint), "critical")


if __name__ == "__main__":
    unittest.main()
