import base64
import binascii
import html
import json
import re
from urllib.parse import parse_qs, urlparse

try:
    from Levenshtein import distance
except ImportError:
    def distance(left, right):
        """Small fallback for environments where python-Levenshtein is absent."""
        previous = list(range(len(right) + 1))
        for i, left_char in enumerate(left, 1):
            current = [i]
            for j, right_char in enumerate(right, 1):
                insert_cost = current[j - 1] + 1
                delete_cost = previous[j] + 1
                replace_cost = previous[j - 1] + (left_char != right_char)
                current.append(min(insert_cost, delete_cost, replace_cost))
            previous = current
        return previous[-1]

from .utils import check_redirect, extract_domain, fetch_url_text, get_domain_age

LEGIT_DOMAINS = [
    "claude.ai",
    "openai.com",
    "google.com",
    "github.com",
]

RISKY_KEYWORDS = ["free", "login", "secure", "bonus", "verify"]
RISKY_TLDS = [".top", ".xyz", ".click", ".buzz"]
RISKY_URL_TERMS = {
    "phishing": 60,
    "malware": 60,
    "ransomware": 60,
    "credential": 35,
    "credentials": 35,
    "password": 30,
    "signin": 20,
    "sign-in": 20,
    "verify-account": 25,
}
KNOWN_TEST_THREAT_HOSTS = {
    "testsafebrowsing.appspot.com": "Google Safe Browsing test threat URL",
}
URL_PATTERN = re.compile(r"https?://[^\s'\"<>|)]+", re.IGNORECASE)
BASE64_PATTERN = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{32,}={0,2}(?![A-Za-z0-9+/=])")
PIPE_TO_SHELL_PATTERN = re.compile(
    r"\b(curl|wget)\b[\s\S]{0,240}\|[\s\S]{0,80}\b(sh|bash|zsh|fish|python|perl|ruby)\b",
    re.IGNORECASE,
)
POWERSHELL_PIPE_EXEC_PATTERN = re.compile(
    r"\b(irm|iwr|invoke-webrequest)\b[\s\S]{0,240}\|[\s\S]{0,80}\b(iex|invoke-expression)\b",
    re.IGNORECASE,
)
COMMAND_SUBSTITUTION_PATTERN = re.compile(r"\$\([^)]+\)", re.IGNORECASE)
OFFICIAL_MENTIONS = {
    "claude": "claude.ai",
    "openai": "openai.com",
    "google": "google.com",
    "github": "github.com",
}
USER_GENERATED_SHARE_PATHS = {
    "claude.ai": ("/share/",),
    "chatgpt.com": ("/share/", "/c/"),
    "poe.com": ("/s/",),
}
TRACKING_PARAMS = {
    "fbclid",
    "gad_campaignid",
    "gad_source",
    "gbraid",
    "gclid",
    "igshid",
    "mc_cid",
    "utm_campaign",
    "utm_medium",
    "utm_source",
}
TRUSTED_INSTALLER_URLS = {
    "https://claude.ai/install.sh",
    "https://claude.ai/install.ps1",
    "https://raw.githubusercontent.com/nvm-sh/nvm/",
}
OFFICIAL_INSTALLER_SIGNAL = "Official installer command from trusted domain"


def check_similarity(domain):
    domain = (domain or "").lower()
    for legit in LEGIT_DOMAINS:
        d = distance(domain, legit)
        if d <= 2 and domain != legit:
            return legit
    return None


def _add_signal(signals, seen, reason, score):
    if reason in seen:
        return
    seen.add(reason)
    signals.append((reason, score))


def _decoded_base64_values(text):
    decoded = []
    for token in BASE64_PATTERN.findall(text or ""):
        padded = token + ("=" * (-len(token) % 4))
        try:
            value = base64.b64decode(padded, validate=True)
        except (binascii.Error, ValueError):
            continue
        try:
            decoded_text = value.decode("utf-8")
        except UnicodeDecodeError:
            continue
        if decoded_text and sum(char.isprintable() for char in decoded_text) / len(decoded_text) > 0.85:
            decoded.append(decoded_text)
    return decoded


def _extract_urls(text):
    return [url.rstrip(".,;]") for url in URL_PATTERN.findall(text or "")]


def _collect_json_strings(value):
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        strings = []
        for item in value.values():
            strings.extend(_collect_json_strings(item))
        return strings
    if isinstance(value, list):
        strings = []
        for item in value:
            strings.extend(_collect_json_strings(item))
        return strings
    return []


def _expand_text_for_analysis(text):
    variants = [text or ""]
    unescaped = html.unescape(text or "")
    if unescaped not in variants:
        variants.append(unescaped)

    for candidate in list(variants):
        try:
            parsed = json.loads(candidate)
        except (TypeError, json.JSONDecodeError):
            continue
        json_text = "\n".join(_collect_json_strings(parsed))
        if json_text and json_text not in variants:
            variants.append(json_text)

    return "\n".join(variants)


def _is_legit_domain(domain):
    return domain in LEGIT_DOMAINS or any(domain.endswith(f".{legit}") for legit in LEGIT_DOMAINS)


def _is_trusted_installer_url(url):
    normalized = (url or "").rstrip("/")
    return any(
        normalized == trusted.rstrip("/") or normalized.startswith(trusted)
        for trusted in TRUSTED_INSTALLER_URLS
    )


def _has_pipe_to_shell(text):
    return bool(
        PIPE_TO_SHELL_PATTERN.search(text or "")
        or POWERSHELL_PIPE_EXEC_PATTERN.search(text or "")
    )


def _is_user_generated_share_url(url, domain):
    paths = USER_GENERATED_SHARE_PATHS.get(domain, ())
    if not paths:
        return False
    path = urlparse(url).path.lower()
    return any(path.startswith(prefix) for prefix in paths)


def _has_tracking_params(url):
    params = set(parse_qs(urlparse(url).query))
    return bool(params & TRACKING_PARAMS)


def _extract_host(url):
    parsed = urlparse(url if "://" in (url or "") else f"https://{url}")
    return (parsed.netloc or parsed.path).split("@")[-1].split(":")[0].lower()


def _url_surface_signals(url):
    signals = []
    seen = set()
    parsed = urlparse(url if "://" in (url or "") else f"https://{url}")
    host = _extract_host(url)
    surface = f"{parsed.path} {parsed.query}".lower()

    if parsed.scheme == "http":
        _add_signal(signals, seen, "Uses plain HTTP instead of HTTPS", 10)

    if host in KNOWN_TEST_THREAT_HOSTS:
        _add_signal(signals, seen, KNOWN_TEST_THREAT_HOSTS[host], 90)

    for term, term_score in RISKY_URL_TERMS.items():
        if term in surface:
            _add_signal(signals, seen, f'URL path/query contains threat term: "{term}"', term_score)

    return signals


def analyze_text(text, source_domain=None):
    reasons = []
    seen = set()
    text = _expand_text_for_analysis(text)
    lowered = text.lower()
    decoded_values = _decoded_base64_values(text)
    decoded_text = "\n".join(decoded_values)
    combined = f"{text}\n{decoded_text}"
    combined_lowered = combined.lower()
    urls = _extract_urls(combined)
    installer_domains = []
    untrusted_installer_domains = []
    trusted_installer_seen = False

    for found_url in urls:
        found_domain = extract_domain(found_url)
        if not found_domain:
            continue
        if any(tool in combined_lowered for tool in ("curl", "wget", "irm", "iwr", "invoke-webrequest")):
            installer_domains.append(found_domain)
            if _is_trusted_installer_url(found_url):
                trusted_installer_seen = True
            elif not _is_legit_domain(found_domain):
                untrusted_installer_domains.append(found_domain)

    has_pipe_execution = _has_pipe_to_shell(combined)

    if has_pipe_execution and not trusted_installer_seen:
        _add_signal(
            reasons,
            seen,
            "Social engineering: install command pipes remote script into shell",
            45,
        )
    elif has_pipe_execution and trusted_installer_seen:
        _add_signal(reasons, seen, OFFICIAL_INSTALLER_SIGNAL, 0)

    if re.search(r"\bcurl\b[^\n|;]*\s(-k|--insecure)\b", combined, re.IGNORECASE):
        _add_signal(
            reasons,
            seen,
            "Social engineering: disables TLS verification with curl -k/--insecure",
            30,
        )

    if decoded_values and _extract_urls(decoded_text):
        _add_signal(
            reasons,
            seen,
            "Social engineering: obfuscated base64 payload hides a URL",
            35,
        )

    if COMMAND_SUBSTITUTION_PATTERN.search(combined):
        _add_signal(
            reasons,
            seen,
            "Social engineering: command substitution hides the real command",
            20,
        )

    for found_url in urls:
        found_domain = extract_domain(found_url)
        if not found_domain:
            continue
        if found_url.lower().startswith("http://"):
            _add_signal(
                reasons,
                seen,
                f"Social engineering: payload URL uses plain HTTP: {found_domain}",
                25,
            )
    hidden_domains = untrusted_installer_domains

    for hidden_domain in sorted(set(hidden_domains)):
        _add_signal(
            reasons,
            seen,
            f"Social engineering: install command downloads from untrusted domain: {hidden_domain}",
            35,
        )

    if source_domain and _is_legit_domain(source_domain):
        for hidden_domain in sorted(set(hidden_domains)):
            if hidden_domain != source_domain and not hidden_domain.endswith(f".{source_domain}"):
                _add_signal(
                    reasons,
                    seen,
                    f"Social engineering: trusted page downloads installer from different domain: {hidden_domain}",
                    30,
                )

    for mention, official_domain in OFFICIAL_MENTIONS.items():
        if mention not in lowered:
            continue
        for hidden_domain in sorted(set(hidden_domains)):
            if hidden_domain != official_domain and not hidden_domain.endswith(f".{official_domain}"):
                _add_signal(
                    reasons,
                    seen,
                    f"Social engineering: mentions {official_domain} but uses different download domain: {hidden_domain}",
                    30,
                )

    trust_phrases = (
        "is it safe",
        "yes, if you use",
        "do not run random",
        "without changing or deleting",
        "copy the command",
    )
    if any(phrase in lowered for phrase in trust_phrases) and (
        (has_pipe_execution and not trusted_installer_seen) or decoded_values
    ):
        _add_signal(
            reasons,
            seen,
            "Social engineering: reassuring language is paired with a risky install command",
            15,
        )

    return {
        "score": min(sum(score for _reason, score in reasons), 100),
        "reasons": [reason for reason, _score in reasons],
        "decoded_urls": sorted(set(_extract_urls(decoded_text))),
    }


def analyze_url(url, fetch_content=True):
    domain = extract_domain(url)
    host = _extract_host(url)

    reasons = []
    score = 0

    for reason, reason_score in _url_surface_signals(url):
        reasons.append(reason)
        score += reason_score

    if not domain:
        reasons.append("Could not extract domain")
        score += 20
    else:
        similar = check_similarity(domain)
        if similar:
            reasons.append(f"Looks like impersonation of {similar}")
            score += 40

        for word in RISKY_KEYWORDS:
            if word in domain:
                reasons.append(f'Contains risky keyword: "{word}"')
                score += 10

        for tld in RISKY_TLDS:
            if domain.endswith(tld):
                reasons.append(f"Suspicious TLD: {tld}")
                score += 20

        age = get_domain_age(domain)
        if age is not None:
            if age < 7:
                reasons.append(f"Very new domain ({age} days)")
                score += 30
            elif age < 30:
                reasons.append(f"New domain ({age} days)")
                score += 15

    is_redirect, chain = check_redirect(url)
    if is_redirect:
        reasons.append("Multiple redirects detected")
        score += 15

    decoded_urls = []
    if fetch_content:
        content = fetch_url_text(url)
        if content:
            text_result = analyze_text(content, source_domain=domain)
            if text_result["reasons"]:
                reasons.extend(text_result["reasons"])
                score += text_result["score"]
            decoded_urls = text_result.get("decoded_urls", [])
        elif domain and _is_user_generated_share_url(url, domain):
            reasons.append(
                "Content scan unavailable for shared page; social engineering could not be verified"
            )
            score += 45

            if _has_tracking_params(url):
                reasons.append("Shared link includes ad/tracking parameters")
                score += 10

    result = {
        "score": min(score, 100),
        "reasons": reasons if reasons else ["No obvious issues detected"],
        "domain": domain,
        "host": host,
    }

    if chain:
        result["redirect_chain"] = chain
    if decoded_urls:
        result["decoded_urls"] = decoded_urls

    return result
