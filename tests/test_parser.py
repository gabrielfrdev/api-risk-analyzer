import unittest
import json
import os
import tempfile
from api_risk_analyzer.parser import load_api, validate_endpoints


class ParserTest(unittest.TestCase):
    def setUp(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".json", mode="w") as f:
            self.valid_json_path = f.name
            json.dump([{"method": "GET", "path": "/test"}], f)
            
        with tempfile.NamedTemporaryFile(delete=False, suffix=".json", mode="w") as f:
            self.invalid_json_path = f.name
            f.write("{ invalid json ")
            
        with tempfile.NamedTemporaryFile(delete=False, suffix=".json", mode="w") as f:
            self.bad_format_path = f.name
            json.dump({"not": "a list"}, f)

    def tearDown(self):
        for path in [self.valid_json_path, self.invalid_json_path, self.bad_format_path]:
            if os.path.exists(path):
                os.remove(path)

    def test_load_valid_json(self):
        data = load_api(self.valid_json_path)
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0]["method"], "GET")

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
        with self.assertRaisesRegex(ValueError, "missing method"):
            validate_endpoints([{"path": "/test"}])

if __name__ == "__main__":
    unittest.main()
