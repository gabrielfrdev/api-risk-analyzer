import unittest

from api_risk_analyzer.rules import (
    check_admin_without_role,
    check_login_without_rate_limit,
    check_unsigned_webhook,
    run_rules,
    score_endpoint,
)


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

    def test_object_id_pattern_ignores_slugs_and_grids(self):
        findings = run_rules([
            {
                "method": "GET",
                "path": "/api/products/{slug}/data/{grid}",
                "auth_required": True,
                "object_authorization": False,
                "response_sensitive_fields": [],
            }
        ])

        self.assertEqual(findings, [])

    def test_object_id_pattern_matches_various_formats(self):
        paths = [
            "/api/users/{id}",
            "/api/users/{userId}",
            "/api/users/{user_id}",
            "/api/users/{uuid}",
            "/api/users/{account_uuid}",
            "/api/users/:id",
            "/api/users/:userId",
            "/api/users/:user_id",
            "/api/users/:uuid",
            "/api/users/:account_uuid"
        ]

        for path in paths:
            findings = run_rules([
                {
                    "method": "GET",
                    "path": path,
                    "auth_required": True,
                    "object_authorization": False,
                    "response_sensitive_fields": [],
                }
            ])
            self.assertEqual(len(findings), 1, f"Failed to match ID pattern in {path}")
            self.assertEqual(findings[0]["rule_id"], "API1-001")

    def test_sensitive_fields_match_common_token_names(self):
        findings = run_rules([
            {
                "method": "GET",
                "path": "/api/session",
                "auth_required": True,
                "response_sensitive_fields": [
                    "accessToken",
                    "refresh_token",
                    "api-key",
                    "displayName",
                ],
            }
        ])

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["rule_id"], "DATA-001")
        self.assertIn("accessToken", findings[0]["evidence"])
        self.assertIn("refresh_token", findings[0]["evidence"])
        self.assertIn("api-key", findings[0]["evidence"])
        self.assertNotIn("displayName", findings[0]["evidence"])

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

    def test_segment_based_matching_avoids_false_positives(self):
        endpoints = [
            {"method": "GET", "path": "/api/administration"},
            {"method": "POST", "path": "/api/webhook_handler"},
            {"method": "POST", "path": "/api/login_history"},
        ]

        self.assertEqual(len(check_admin_without_role(endpoints)), 0)
        self.assertEqual(len(check_unsigned_webhook(endpoints)), 0)
        self.assertEqual(len(check_login_without_rate_limit(endpoints)), 0)

        endpoints_positive = [
            {"method": "GET", "path": "/api/admins"},
            {"method": "POST", "path": "/api/webhooks/github"},
            {"method": "POST", "path": "/api/auth/sign-in"},
        ]

        self.assertEqual(len(check_admin_without_role(endpoints_positive)), 1)
        self.assertEqual(len(check_unsigned_webhook(endpoints_positive)), 1)
        self.assertEqual(len(check_login_without_rate_limit(endpoints_positive)), 1)


if __name__ == "__main__":
    unittest.main()

