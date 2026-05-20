import unittest
import json
import os
import tempfile
from api_risk_analyzer.openapi import parse_openapi


class OpenAPITest(unittest.TestCase):
    def write_schema(self, schema):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".json", mode="w") as file:
            json.dump(schema, file)
            return file.name

    def setUp(self):
        schema = {
            "openapi": "3.0.0",
            "security": [{"Bearer": []}],
            "paths": {
                "/api/public": {
                    "get": {
                        "security": []
                    }
                },
                "/api/private": {
                    "post": {}
                }
            }
        }
        self.openapi_path = self.write_schema(schema)

    def tearDown(self):
        if os.path.exists(self.openapi_path):
            os.remove(self.openapi_path)

    def test_parse_openapi(self):
        with open(self.openapi_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        endpoints = parse_openapi(data)
        self.assertEqual(len(endpoints), 2)

        public = next(e for e in endpoints if e["path"] == "/api/public")
        self.assertFalse(public["auth_required"])
        self.assertTrue(public["public"])

        private = next(e for e in endpoints if e["path"] == "/api/private")
        self.assertTrue(private["auth_required"])
        self.assertFalse(private["public"])

    def test_parse_openapi_extensions(self):
        schema = {
            "openapi": "3.0.0",
            "security": [{"Bearer": []}],
            "paths": {
                "/api/users/{id}": {
                    "x-object-authorization": True,
                    "get": {
                        "x-role-required": "user",
                        "x-rate-limit": True,
                        "x-response-sensitive-fields": [" email ", "", "token"],
                    }
                },
                "/api/webhooks/payments": {
                    "post": {
                        "security": [],
                        "x-signature-required": False,
                    }
                }
            }
        }

        endpoints = parse_openapi(schema)
        user_route = next(e for e in endpoints if e["path"] == "/api/users/{id}")
        self.assertTrue(user_route["object_authorization"])
        self.assertEqual(user_route["role_required"], "user")
        self.assertTrue(user_route["rate_limit"])
        self.assertEqual(user_route["response_sensitive_fields"], ["email", "token"])

        webhook_route = next(e for e in endpoints if e["path"] == "/api/webhooks/payments")
        self.assertFalse(webhook_route["auth_required"])
        self.assertTrue(webhook_route["public"])
        self.assertFalse(webhook_route["signature_required"])

    def test_operation_extension_overrides_path_extension(self):
        schema = {
            "openapi": "3.0.0",
            "paths": {
                "/api/accounts/{accountId}": {
                    "x-rate-limit": False,
                    "get": {
                        "x-rate-limit": True,
                    }
                }
            }
        }

        endpoint = parse_openapi(schema)[0]
        self.assertTrue(endpoint["rate_limit"])

    def test_empty_security_requirement_allows_public_access(self):
        schema = {
            "openapi": "3.0.0",
            "security": [{}, {"Bearer": []}],
            "paths": {
                "/api/status": {
                    "get": {}
                }
            }
        }

        endpoint = parse_openapi(schema)[0]
        self.assertFalse(endpoint["auth_required"])
        self.assertTrue(endpoint["public"])

    def test_invalid_extension_type_is_rejected(self):
        schema = {
            "openapi": "3.0.0",
            "paths": {
                "/api/users": {
                    "get": {
                        "x-rate-limit": "true",
                    }
                }
            }
        }

        with self.assertRaisesRegex(ValueError, "x-rate-limit must be a boolean"):
            parse_openapi(schema)

    def test_invalid_paths_object(self):
        schema = {
            "openapi": "3.0.0",
            "paths": ["/api/users"]
        }
        with self.assertRaisesRegex(ValueError, "OpenAPI 'paths' must be an object"):
            parse_openapi(schema)

    def test_invalid_path_item_object(self):
        schema = {
            "openapi": "3.0.0",
            "paths": {
                "/api/users": "GET"
            }
        }
        with self.assertRaisesRegex(ValueError, "OpenAPI path '/api/users' must be an object"):
            parse_openapi(schema)

    def test_infer_response_fields(self):
        schema = {
            "openapi": "3.0.0",
            "paths": {
                "/api/auth/login": {
                    "post": {
                        "responses": {
                            "200": {
                                "content": {
                                    "application/json": {
                                        "schema": {
                                            "type": "object",
                                            "properties": {
                                                "token": {"type": "string"},
                                                "accessToken": {"type": "string"},
                                                "user": {
                                                    "type": "object",
                                                    "properties": {
                                                        "password": {"type": "string"},
                                                        "name": {"type": "string"}
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        endpoint = parse_openapi(schema)[0]
        self.assertIn("token", endpoint["response_sensitive_fields"])
        self.assertIn("accessToken", endpoint["response_sensitive_fields"])
        self.assertIn("password", endpoint["response_sensitive_fields"])
        self.assertNotIn("name", endpoint["response_sensitive_fields"])

    def test_parse_openapi_validates_security_is_list(self):
        schema = {
            "openapi": "3.0.0",
            "security": {"BearerAuth": []},
            "paths": {"/api/test": {"get": {}}},
        }
        with self.assertRaisesRegex(ValueError, "OpenAPI 'security' must be a list"):
            parse_openapi(schema)


if __name__ == "__main__":
    unittest.main()

