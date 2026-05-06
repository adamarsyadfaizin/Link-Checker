from datetime import date, datetime
from urllib.parse import urlparse

try:
    import requests
except ImportError:
    requests = None

try:
    import tldextract
except ImportError:
    tldextract = None

_TLD_EXTRACTOR = (
    tldextract.TLDExtract(suffix_list_urls=()) if tldextract is not None else None
)

try:
    import whois
except ImportError:
    whois = None


def _ensure_scheme(url):
    cleaned = (url or "").strip()
    if not cleaned:
        return ""
    if "://" not in cleaned:
        return f"https://{cleaned}"
    return cleaned


def extract_domain(url):
    normalized_url = _ensure_scheme(url)
    if not normalized_url:
        return ""

    if _TLD_EXTRACTOR is not None:
        extracted = _TLD_EXTRACTOR(normalized_url)
        if extracted.domain and extracted.suffix:
            return f"{extracted.domain}.{extracted.suffix}".lower()

    parsed = urlparse(normalized_url)
    host = parsed.netloc or parsed.path
    host = host.split("@")[-1].split(":")[0].strip(".").lower()

    parts = [part for part in host.split(".") if part]
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return host


def _first_creation_date(value):
    if isinstance(value, list):
        return next((item for item in value if item), None)
    return value


def _parse_creation_date(value):
    value = _first_creation_date(value)
    if isinstance(value, datetime):
        return value
    if isinstance(value, date):
        return datetime.combine(value, datetime.min.time())
    if isinstance(value, str):
        for fmt in ("%Y-%m-%d", "%Y-%m-%d %H:%M:%S", "%d-%b-%Y"):
            try:
                return datetime.strptime(value[:19], fmt)
            except ValueError:
                continue
    return None


def get_domain_age(domain):
    if whois is None or not domain:
        return None

    try:
        data = whois.whois(domain)
        created_at = _parse_creation_date(getattr(data, "creation_date", None))
        if created_at is None and isinstance(data, dict):
            created_at = _parse_creation_date(data.get("creation_date"))
        if created_at is None:
            return None

        if created_at.tzinfo is not None:
            now = datetime.now(created_at.tzinfo)
        else:
            now = datetime.now()

        return max((now - created_at).days, 0)
    except Exception:
        return None


def check_redirect(url):
    if requests is None:
        return False, []

    try:
        response = requests.get(_ensure_scheme(url), timeout=5, allow_redirects=True)
        if len(response.history) > 1:
            return True, [redirect.url for redirect in response.history]
        return False, []
    except Exception:
        return False, []


def fetch_url_text(url, max_chars=300000):
    if requests is None:
        return None

    try:
        response = requests.get(
            _ensure_scheme(url),
            timeout=8,
            allow_redirects=True,
            headers={"User-Agent": "link-check/0.1"},
        )
        content_type = response.headers.get("content-type", "").lower()
        if content_type and not any(
            kind in content_type
            for kind in ("text/", "html", "json", "xml", "javascript")
        ):
            return None
        return response.text[:max_chars]
    except Exception:
        return None
