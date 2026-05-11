import unittest
import json
import os
import tempfile
from api_risk_analyzer.parser import load_api, validate_endpoints


class ParserTest(unittest.TestCase):
    def write_json_file(self, data):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".json", mode="w") as file:
            json.dump(data, file)
            return file.name

    def setUp(self):
        self.valid_json_path = self.write_json_file([{"method": "GET", "path": "/test"}])

        with tempfile.NamedTemporaryFile(delete=False, suffix=".json", mode="w") as f:
            self.invalid_json_path = f.name
            f.write("{ invalid json ")

        self.bad_format_path = self.write_json_file({"not": "a list"})

    def tearDown(self):
        for path in [self.valid_json_path, self.invalid_json_path, self.bad_format_path]:
            if os.path.exists(path):
                os.remove(path)

    def test_load_valid_json(self):
        data = load_api(self.valid_json_path)
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0]["method"], "GET")

    def test_load_normalizes_endpoint_strings(self):
        path = self.write_json_file([
            {
                "method": " get ",
                "path": " /api/users ",
                "response_sensitive_fields": [" token ", "", " cpf "],
            }
        ])
        try:
            data = load_api(path)
        finally:
            if os.path.exists(path):
                os.remove(path)

        self.assertEqual(data[0]["method"], "GET")
        self.assertEqual(data[0]["path"], "/api/users")
        self.assertEqual(data[0]["response_sensitive_fields"], ["token", "cpf"])

    def test_file_not_found(self):
        with self.assertRaisesRegex(ValueError, "input file not found"):
            load_api("non_existent_file.json")

    def test_invalid_json(self):
        with self.assertRaisesRegex(ValueError, "invalid json"):
            load_api(self.invalid_json_path)

    def test_bad_format(self):
        with self.assertRaisesRegex(ValueError, "Input must be a JSON array"):
            load_api(self.bad_format_path)

    def test_validate_endpoints_missing_method(self):
        with self.assertRaisesRegex(ValueError, "missing a valid method"):
            validate_endpoints([{"path": "/test"}])

    def test_validate_endpoints_invalid_boolean(self):
        with self.assertRaisesRegex(ValueError, "field 'auth_required' must be a boolean"):
            validate_endpoints([{"method": "GET", "path": "/test", "auth_required": "false"}])

    def test_validate_endpoints_invalid_list(self):
        with self.assertRaisesRegex(ValueError, "field 'response_sensitive_fields' must be a list"):
            validate_endpoints([{"method": "GET", "path": "/test", "response_sensitive_fields": "password"}])

    def test_validate_endpoints_rejects_non_string_sensitive_fields(self):
        with self.assertRaisesRegex(ValueError, "field 'response_sensitive_fields' must contain strings"):
            validate_endpoints([{"method": "GET", "path": "/test", "response_sensitive_fields": ["token", 123]}])

if __name__ == "__main__":
    unittest.main()
