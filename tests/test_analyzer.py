import unittest
from unittest.mock import patch

from link_check.analyzer import analyze_url, check_similarity


class AnalyzerTests(unittest.TestCase):
    def test_similarity_flags_typosquat(self):
        self.assertEqual(check_similarity("goggle.com"), "google.com")
        self.assertEqual(check_similarity("openaii.com"), "openai.com")

    def test_similarity_ignores_exact_legit_domain(self):
        self.assertIsNone(check_similarity("google.com"))

    def test_safe_url_has_low_score(self):
        with patch("link_check.analyzer.get_domain_age", return_value=None), patch(
            "link_check.analyzer.check_redirect", return_value=(False, [])
        ):
            result = analyze_url("https://google.com")

        self.assertEqual(result["score"], 0)
        self.assertEqual(result["reasons"], ["No obvious issues detected"])
        self.assertEqual(result["domain"], "google.com")

    def test_keyword_and_tld_increase_score(self):
        with patch("link_check.analyzer.get_domain_age", return_value=None), patch(
            "link_check.analyzer.check_redirect", return_value=(False, [])
        ):
            result = analyze_url("https://secure-login-example.xyz")

        self.assertEqual(result["score"], 40)
        self.assertIn('Contains risky keyword: "secure"', result["reasons"])
        self.assertIn('Contains risky keyword: "login"', result["reasons"])
        self.assertIn("Suspicious TLD: .xyz", result["reasons"])

    def test_new_domain_increases_score(self):
        with patch("link_check.analyzer.get_domain_age", return_value=3), patch(
            "link_check.analyzer.check_redirect", return_value=(False, [])
        ):
            result = analyze_url("https://example.com")

        self.assertEqual(result["score"], 30)
        self.assertIn("Very new domain (3 days)", result["reasons"])

    def test_redirect_chain_is_reported(self):
        chain = ["https://a.test", "https://b.test"]
        with patch("link_check.analyzer.get_domain_age", return_value=None), patch(
            "link_check.analyzer.check_redirect", return_value=(True, chain)
        ):
            result = analyze_url("https://example.com")

        self.assertEqual(result["score"], 15)
        self.assertIn("Multiple redirects detected", result["reasons"])
        self.assertEqual(result["redirect_chain"], chain)


if __name__ == "__main__":
    unittest.main()
