import unittest
from unittest.mock import patch
import os
import json
import tempfile
from api_risk_analyzer.cli import main


class CliTest(unittest.TestCase):
    def setUp(self):
        self.mock_write_json = patch("api_risk_analyzer.cli.write_json").start()
        self.mock_write_markdown = patch("api_risk_analyzer.cli.write_markdown").start()

        with tempfile.NamedTemporaryFile(delete=False, suffix=".json", mode="w") as f:
            self.sample_path = f.name
            json.dump([
                {
                    "method": "GET",
                    "path": "/api/users/{id}",
                    "public": False,
                    "auth_required": True,
                    "object_authorization": False
                }
            ], f)

    def tearDown(self):
        patch.stopall()
        if os.path.exists(self.sample_path):
            os.remove(self.sample_path)

    @patch("sys.stdout")
    def test_cli_fail_on_high_with_critical_finding(self, mock_stdout):
        with patch("sys.argv", ["analyzer.py", "--input", self.sample_path, "--fail-on", "high"]):
            exit_code = main()
            self.assertEqual(exit_code, 1)

    @patch("sys.stdout")
    def test_cli_fail_on_low_with_critical_finding(self, mock_stdout):
        with patch("sys.argv", ["analyzer.py", "--input", self.sample_path, "--fail-on", "low"]):
            exit_code = main()
            self.assertEqual(exit_code, 1)

    @patch("sys.stdout")
    def test_cli_no_fail_on(self, mock_stdout):
        with patch("sys.argv", ["analyzer.py", "--input", self.sample_path]):
            exit_code = main()
            self.assertEqual(exit_code, 0)

    @patch("sys.stdout")
    def test_cli_file_not_found(self, mock_stdout):
        with patch("sys.argv", ["analyzer.py", "--input", "non_existent.json"]):
            exit_code = main()
            self.assertEqual(exit_code, 1)

    @patch("sys.stdout")
    def test_cli_default_markdown_output(self, mock_stdout):
        with patch("sys.argv", ["analyzer.py", "--input", self.sample_path, "--format", "markdown"]):
            main()
            self.mock_write_markdown.assert_called_once()
            args, _ = self.mock_write_markdown.call_args
            self.assertEqual(args[1], "reports/generated-report.md")

    @patch("builtins.print")
    def test_cli_prints_severity_summary(self, mock_print):
        with patch("sys.argv", ["analyzer.py", "--input", self.sample_path]):
            main()
            mock_print.assert_any_call("findings: 1 (critical: 1)")

if __name__ == "__main__":
    unittest.main()
