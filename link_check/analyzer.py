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

from .utils import check_redirect, extract_domain, get_domain_age

LEGIT_DOMAINS = [
    "claude.ai",
    "openai.com",
    "google.com",
    "github.com",
]

RISKY_KEYWORDS = ["free", "login", "secure", "bonus", "verify"]
RISKY_TLDS = [".top", ".xyz", ".click", ".buzz"]


def check_similarity(domain):
    domain = (domain or "").lower()
    for legit in LEGIT_DOMAINS:
        d = distance(domain, legit)
        if d <= 2 and domain != legit:
            return legit
    return None


def analyze_url(url):
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

    result = {
        "score": min(score, 100),
        "reasons": reasons if reasons else ["No obvious issues detected"],
        "domain": domain,
    }

    if chain:
        result["redirect_chain"] = chain

    return result
