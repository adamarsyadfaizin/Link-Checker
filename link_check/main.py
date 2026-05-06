import sys

try:
    from colorama import Fore, Style, init
except ImportError:
    class _EmptyColor:
        BLACK = "\033[30m"
        BLUE = "\033[34m"
        RED = "\033[31m"
        YELLOW = "\033[33m"
        GREEN = "\033[32m"
        CYAN = "\033[36m"
        MAGENTA = "\033[35m"
        WHITE = "\033[37m"
        BRIGHT = "\033[1m"
        DIM = "\033[2m"
        NORMAL = "\033[22m"
        RESET_ALL = "\033[0m"

    Fore = _EmptyColor()
    Style = _EmptyColor()

    def init(autoreset=False):
        return None

from .analyzer import analyze_text, analyze_url


CYAN = Fore.CYAN
GREEN = Fore.GREEN
MAGENTA = Fore.MAGENTA
RED = Fore.RED
YELLOW = Fore.YELLOW
WHITE = Fore.WHITE
BRIGHT = Style.BRIGHT
DIM = Style.DIM
RESET = Style.RESET_ALL


def _usage():
    return "Usage:\n  link-check <url>\n  link-check explain <url>\n  python run.py"


def _parse_args(argv):
    if len(argv) == 2:
        return argv[1], False

    if len(argv) == 3 and argv[1] == "explain":
        return argv[2], True

    return None, False


def _advice(score):
    if score > 70:
        return f"{RED}{BRIGHT}Advice: DO NOT enter credentials [DANGER]{RESET}"
    if score > 40:
        return f"{YELLOW}{BRIGHT}Advice: Be cautious [WARNING]{RESET}"
    return f"{GREEN}{BRIGHT}Advice: Looks safe [OK]{RESET}"


def _risk_style(score):
    if score > 70:
        return RED, "CRITICAL"
    if score > 40:
        return YELLOW, "ELEVATED"
    return GREEN, "LOW"


def _score_bar(score, width=24):
    filled = round((score / 100) * width)
    empty = width - filled
    color, label = _risk_style(score)
    return f"{color}{'#' * filled}{DIM}{'-' * empty}{RESET} {color}{label}{RESET}"


def _signal_color(reason):
    if reason == "No obvious issues detected":
        return GREEN
    if (
        reason.startswith("Looks like impersonation of")
        or reason.startswith("Very new domain")
        or reason.startswith("Social engineering:")
    ):
        return RED
    if (
        reason.startswith("Suspicious TLD")
        or reason == "Multiple redirects detected"
        or reason.startswith("Content scan unavailable")
        or reason == "Shared link includes ad/tracking parameters"
    ):
        return YELLOW
    return MAGENTA


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
    if reason.startswith("Social engineering: install command pipes"):
        return (
            "Piping curl or wget directly into a shell runs remote code immediately. "
            "That is one of the highest-risk install patterns."
        )
    if reason.startswith("Social engineering: disables TLS verification"):
        return (
            "The -k/--insecure flag ignores certificate checks, making it easier "
            "for attackers or broken infrastructure to serve unsafe code."
        )
    if reason.startswith("Social engineering: obfuscated base64"):
        return (
            "Base64 can hide the real URL or command from casual inspection. "
            "Install instructions should not need hidden payloads."
        )
    if reason.startswith("Social engineering: command substitution"):
        return (
            "Command substitution runs another command first, often hiding the "
            "actual download location from the visible install snippet."
        )
    if reason.startswith("Social engineering: payload URL uses plain HTTP"):
        return (
            "Plain HTTP can be modified in transit. Installers should use HTTPS "
            "from a clearly trusted source."
        )
    if reason.startswith("Social engineering: install command downloads"):
        return (
            "The visible page may look legitimate, but the command downloads code "
            "from a different domain that should be treated as untrusted."
        )
    if reason.startswith("Social engineering: trusted page downloads"):
        return (
            "A legitimate host can still contain unsafe shared content. The page "
            "domain is trusted, but the installer payload points outside it."
        )
    if reason.startswith("Social engineering: mentions"):
        return (
            "This is a brand-mismatch signal: the text claims one trusted service, "
            "but the executable payload points somewhere else."
        )
    if reason.startswith("Social engineering: reassuring language"):
        return (
            "Attackers often pair high-risk commands with calming safety claims. "
            "The command behavior matters more than the reassurance."
        )
    if reason.startswith("Content scan unavailable for shared page"):
        return (
            "This is a user-shared page from a trusted platform. The domain is legitimate, "
            "but the tool could not inspect the shared content, so it cannot clear it as safe."
        )
    if reason == "Shared link includes ad/tracking parameters":
        return (
            "Tracking parameters do not prove danger, but they are common in promoted links "
            "and make the source/context harder to trust."
        )
    if reason == "Could not extract domain":
        return "The URL could not be parsed into a registered domain for reliable checks."
    return "No extra explanation is available for this signal."


def _print_analysis_result(target, result, detailed=False, domain=None):
    score = result["score"]
    score_color, _label = _risk_style(score)

    print("\n" + f"{CYAN}{BRIGHT}" + "=" * 58 + RESET)
    print(f"{CYAN}{BRIGHT}:: Link Analysis Result ::{RESET}")
    print(f"{CYAN}{BRIGHT}" + "=" * 58 + RESET)
    print(f"{DIM}TARGET{RESET}  {WHITE}{target}{RESET}")
    print(f"{DIM}DOMAIN{RESET}  {WHITE}{domain or result.get('domain') or 'unknown'}{RESET}")
    print(f"{DIM}SCORE {RESET}  {score_color}{BRIGHT}{score:>3}/100{RESET}  {_score_bar(score)}")

    print(f"\n{CYAN}{BRIGHT}[ SIGNALS ]{RESET}")
    for reason in result["reasons"]:
        color = _signal_color(reason)
        print(f"{color}> {reason}{RESET}")
        if detailed:
            print(f"{DIM}  {_explain_reason(reason)}{RESET}")

    redirect_chain = result.get("redirect_chain", [])
    if redirect_chain:
        print(f"\n{CYAN}{BRIGHT}[ REDIRECT TRACE ]{RESET}")
        for index, redirected_url in enumerate(redirect_chain, 1):
            print(f"{MAGENTA}{index:02d}{RESET} -> {redirected_url}")

    decoded_urls = result.get("decoded_urls", [])
    if decoded_urls:
        print(f"\n{CYAN}{BRIGHT}[ DECODED URLS ]{RESET}")
        for index, decoded_url in enumerate(decoded_urls, 1):
            print(f"{MAGENTA}{index:02d}{RESET} -> {decoded_url}")

    print(f"\n{_advice(score)}")
    return result


def print_result(url, detailed=False):
    result = analyze_url(url)
    return _print_analysis_result(url, result, detailed=detailed)


def print_text_result(text, detailed=True):
    result = analyze_text(text)
    if not result["reasons"]:
        result["reasons"] = ["No obvious issues detected"]
    return _print_analysis_result("pasted content", result, detailed=detailed, domain="n/a")


def main(argv=None):
    init(autoreset=False)
    argv = sys.argv if argv is None else argv
    url, detailed = _parse_args(argv)

    if not url:
        print(_usage())
        return 2

    print_result(url, detailed=detailed)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
