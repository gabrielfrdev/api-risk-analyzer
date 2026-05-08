import unittest
import json
import os
import tempfile
from api_risk_analyzer.openapi import parse_openapi


class OpenAPITest(unittest.TestCase):
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
        with tempfile.NamedTemporaryFile(delete=False, suffix=".json", mode="w") as f:
            self.openapi_path = f.name
            json.dump(schema, f)

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

if __name__ == "__main__":
    unittest.main()
