from datetime import datetime, timedelta
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from link_check.utils import check_redirect, extract_domain, get_domain_age


class UtilsTests(unittest.TestCase):
    def test_extract_domain_uses_registered_domain(self):
        self.assertEqual(extract_domain("https://login.accounts.google.com/path"), "google.com")

    def test_check_redirect_detects_multiple_hops(self):
        response = SimpleNamespace(
            history=[
                SimpleNamespace(url="https://first.test"),
                SimpleNamespace(url="https://second.test"),
            ]
        )

        with patch("link_check.utils.requests", Mock(get=Mock(return_value=response))):
            is_redirect, chain = check_redirect("https://example.com")

        self.assertTrue(is_redirect)
        self.assertEqual(chain, ["https://first.test", "https://second.test"])

    def test_get_domain_age_returns_days(self):
        created_at = datetime.now() - timedelta(days=5)
        fake_whois = Mock(whois=Mock(return_value=SimpleNamespace(creation_date=created_at)))

        with patch("link_check.utils.whois", fake_whois):
            self.assertEqual(get_domain_age("example.com"), 5)


if __name__ == "__main__":
    unittest.main()
