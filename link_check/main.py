import sys

try:
    from colorama import Fore, Style, init
except ImportError:
    class _EmptyColor:
        RED = ""
        YELLOW = ""
        GREEN = ""
        CYAN = ""
        RESET_ALL = ""

    Fore = _EmptyColor()
    Style = _EmptyColor()

    def init():
        return None

from .analyzer import analyze_url


def _usage():
    return "Usage:\n  link-check <url>\n  link-check explain <url>"


def _parse_args(argv):
    if len(argv) == 2:
        return argv[1], False

    if len(argv) == 3 and argv[1] == "explain":
        return argv[2], True

    return None, False


def _advice(score):
    if score > 70:
        return f"{Fore.RED}Advice: DO NOT enter credentials ❌{Style.RESET_ALL}"
    if score > 40:
        return f"{Fore.YELLOW}Advice: Be cautious ⚠{Style.RESET_ALL}"
    return f"{Fore.GREEN}Advice: Looks safe ✅{Style.RESET_ALL}"


def _explain_reason(reason):
    if reason.startswith("Looks like impersonation of"):
        return (
            "The domain is only a tiny edit away from a trusted domain. "
            "That pattern is often used for typo-squatting and fake login pages."
        )
    if reason.startswith("Contains risky keyword"):
        return (
            "Attackers often add words like login, secure, verify, bonus, or free "
            "to make a domain feel urgent or official."
        )
    if reason.startswith("Suspicious TLD"):
        return (
            "This top-level domain is commonly abused in disposable campaigns. "
            "It is not automatically malicious, but it raises the risk score."
        )
    if reason.startswith("Very new domain") or reason.startswith("New domain"):
        return (
            "New domains have less reputation history. Freshly registered domains "
            "are frequently used in phishing and short-lived scam campaigns."
        )
    if reason == "Multiple redirects detected":
        return (
            "Several redirects can hide the final destination and are often used "
            "to route users through tracking or evasive infrastructure."
        )
    if reason == "Could not extract domain":
        return "The URL could not be parsed into a registered domain for reliable checks."
    return "No extra explanation is available for this signal."


def main(argv=None):
    init()
    argv = sys.argv if argv is None else argv
    url, detailed = _parse_args(argv)

    if not url:
        print(_usage())
        return 2

    result = analyze_url(url)
    score = result["score"]

    print("\n" + "=" * 40)
    print(f"{Fore.CYAN}🔍 Link Analysis Result{Style.RESET_ALL}")
    print("=" * 40)
    print(f"URL: {url}")
    print(f"Domain: {result.get('domain') or 'unknown'}")
    print(f"Score: {score}/100")

    print("\nReasons:")
    for reason in result["reasons"]:
        print(f"- {reason}")
        if detailed:
            print(f"  {_explain_reason(reason)}")

    redirect_chain = result.get("redirect_chain", [])
    if redirect_chain:
        print("\nRedirect chain:")
        for index, redirected_url in enumerate(redirect_chain, 1):
            print(f"{index}. {redirected_url}")

    print(f"\n{_advice(score)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
