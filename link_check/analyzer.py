import base64
import binascii
import re

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
URL_PATTERN = re.compile(r"https?://[^\s'\"<>|)]+", re.IGNORECASE)
BASE64_PATTERN = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{32,}={0,2}(?![A-Za-z0-9+/=])")
PIPE_TO_SHELL_PATTERN = re.compile(
    r"\b(curl|wget)\b[\s\S]{0,240}\|[\s\S]{0,80}\b(sh|bash|zsh|fish|python|perl|ruby)\b",
    re.IGNORECASE,
)
COMMAND_SUBSTITUTION_PATTERN = re.compile(r"\$\([^)]+\)", re.IGNORECASE)
OFFICIAL_MENTIONS = {
    "claude": "claude.ai",
    "openai": "openai.com",
    "google": "google.com",
    "github": "github.com",
}


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


def _is_legit_domain(domain):
    return domain in LEGIT_DOMAINS or any(domain.endswith(f".{legit}") for legit in LEGIT_DOMAINS)


def analyze_text(text, source_domain=None):
    reasons = []
    seen = set()
    text = text or ""
    lowered = text.lower()
    decoded_values = _decoded_base64_values(text)
    decoded_text = "\n".join(decoded_values)
    combined = f"{text}\n{decoded_text}"
    combined_lowered = combined.lower()

    if PIPE_TO_SHELL_PATTERN.search(combined):
        _add_signal(
            reasons,
            seen,
            "Social engineering: install command pipes remote script into shell",
            45,
        )

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

    urls = _extract_urls(combined)
    hidden_domains = []
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
        if any(tool in combined_lowered for tool in ("curl", "wget")) and not _is_legit_domain(found_domain):
            hidden_domains.append(found_domain)

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
        PIPE_TO_SHELL_PATTERN.search(combined) or decoded_values
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

    reasons = []
    score = 0

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

    result = {
        "score": min(score, 100),
        "reasons": reasons if reasons else ["No obvious issues detected"],
        "domain": domain,
    }

    if chain:
        result["redirect_chain"] = chain
    if decoded_urls:
        result["decoded_urls"] = decoded_urls

    return result
