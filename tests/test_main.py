import io
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

from link_check.main import main


class MainTests(unittest.TestCase):
    def test_missing_url_prints_usage(self):
        output = io.StringIO()

        with redirect_stdout(output):
            exit_code = main(["link-check"])

        self.assertEqual(exit_code, 2)
        self.assertIn("Usage:", output.getvalue())

    def test_standard_output_includes_advice(self):
        with patch(
            "link_check.main.analyze_url",
            return_value={
                "score": 0,
                "reasons": ["No obvious issues detected"],
                "domain": "google.com",
            },
        ):
            output = io.StringIO()
            with redirect_stdout(output):
                exit_code = main(["link-check", "https://google.com"])

        text = output.getvalue()
        self.assertEqual(exit_code, 0)
        self.assertIn("Link Analysis Result", text)
        self.assertIn("Advice: Looks safe", text)

    def test_explain_mode_prints_longer_explanation(self):
        with patch(
            "link_check.main.analyze_url",
            return_value={
                "score": 40,
                "reasons": ["Looks like impersonation of google.com"],
                "domain": "goggle.com",
            },
        ):
            output = io.StringIO()
            with redirect_stdout(output):
                exit_code = main(["link-check", "explain", "https://goggle.com"])

        text = output.getvalue()
        self.assertEqual(exit_code, 0)
        self.assertIn("typo-squatting", text)


if __name__ == "__main__":
    unittest.main()
