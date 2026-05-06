from link_check.main import print_result, print_text_result

try:
    from colorama import Fore, Style, init
except ImportError:
    class _EmptyColor:
        CYAN = "\033[36m"
        GREEN = "\033[32m"
        MAGENTA = "\033[35m"
        RED = "\033[31m"
        YELLOW = "\033[33m"
        WHITE = "\033[37m"
        BRIGHT = "\033[1m"
        DIM = "\033[2m"
        RESET_ALL = "\033[0m"

    Fore = _EmptyColor()
    Style = _EmptyColor()

    def init(autoreset=False):
        return None


CYAN = Fore.CYAN
GREEN = Fore.GREEN
MAGENTA = Fore.MAGENTA
RED = Fore.RED
YELLOW = Fore.YELLOW
WHITE = Fore.WHITE
BRIGHT = Style.BRIGHT
DIM = Style.DIM
RESET = Style.RESET_ALL


def _line(width=62, color=CYAN):
    print(f"{color}{BRIGHT}" + "=" * width + f"{RESET}")


def _print_welcome():
    print()
    _line()
    print(f"{CYAN}{BRIGHT} __    ___ _   _ _  __        ___ _____ ____ _   _ {RESET}")
    print(f"{CYAN}{BRIGHT} \\ \\  / / | | | | |/ /  ___  / _ \\_   _/ ___| | | |{RESET}")
    print(f"{MAGENTA}{BRIGHT}  \\ \\/ /| | | | | ' /  / __|| | | || || |   | |_| |{RESET}")
    print(f"{MAGENTA}{BRIGHT}   \\  / | |_| | | . \\  \\__ \\| |_| || || |___|  _  |{RESET}")
    print(f"{GREEN}{BRIGHT}    \\/   \\___/|_|_|\\_\\ |___/ \\___/ |_| \\____|_| |_|{RESET}")
    _line()
    print(f"{WHITE}{BRIGHT}Welcome to Link Check Toolkit{RESET}")
    print(f"{MAGENTA}{BRIGHT}by Adam{RESET} {DIM}| GitHub: https://github.com/adamarsyadfaizin{RESET}")
    print(f"{DIM}Cyber-style URL risk scanner for fast terminal checks.{RESET}")
    print()
    print(f"{CYAN}+----+----------------------------+{RESET}")
    print(f"{CYAN}| {GREEN}1{CYAN}  | {WHITE}Link checker{CYAN}               |{RESET}")
    print(f"{CYAN}| {RED}0{CYAN}  | {WHITE}Exit{CYAN}                       |{RESET}")
    print(f"{CYAN}+----+----------------------------+{RESET}")


def _print_link_checker_help():
    print(f"\n{CYAN}{BRIGHT}[ COMMAND DECK ]{RESET}")
    print(f"{GREEN}check <url>{RESET}       Analyze a URL")
    print(f"{MAGENTA}explain <url>{RESET}     Analyze with detailed explanations")
    print(f"{MAGENTA}scantext{RESET}          Paste suspicious text, then type END")
    print(f"{YELLOW}help{RESET}              Show this help")
    print(f"{YELLOW}back{RESET}              Return to main menu")
    print(f"{RED}exit{RESET}              Close the app")


def _split_command(command):
    parts = command.strip().split(maxsplit=1)
    if not parts:
        return "", ""
    if len(parts) == 1:
        return parts[0].lower(), ""
    return parts[0].lower(), parts[1].strip()


def link_checker_loop():
    print(f"\n{GREEN}{BRIGHT}[SYSTEM ONLINE]{RESET} Link checker ready.")
    _print_link_checker_help()

    while True:
        command, value = _split_command(input(f"\n{CYAN}{BRIGHT}link-check{RESET}{MAGENTA}>{RESET} "))

        if command in ("back", "menu"):
            return "menu"
        if command in ("exit", "quit", "q"):
            return "exit"
        if command in ("help", "?"):
            _print_link_checker_help()
            continue
        if command == "scantext":
            print(f"{CYAN}Paste suspicious content below. Type END on its own line to scan.{RESET}")
            lines = []
            while True:
                line = input()
                if line.strip() == "END":
                    break
                lines.append(line)
            text = "\n".join(lines).strip()
            if not text:
                print(f"{YELLOW}No text entered.{RESET}")
                continue
            print_text_result(text, detailed=True)
            continue
        if command in ("check", "explain"):
            if not value:
                print(f"{YELLOW}Please enter a URL. Example: check https://google.com{RESET}")
                continue
            print_result(value, detailed=(command == "explain"))
            continue

        print(f"{RED}Unknown command.{RESET} Type 'help' to see available commands.")


def main():
    init(autoreset=False)

    while True:
        _print_welcome()
        choice = input(f"\n{CYAN}{BRIGHT}Choose menu{RESET}{MAGENTA}>{RESET} ").strip().lower()

        if choice in ("1", "link", "link checker", "checker"):
            result = link_checker_loop()
            if result == "exit":
                print(f"\n{CYAN}Session closed. Stay safe online.{RESET}")
                return 0
            continue

        if choice in ("0", "exit", "quit", "q"):
            print(f"\n{CYAN}Session closed. Stay safe online.{RESET}")
            return 0

        print(f"{RED}Invalid choice.{RESET} Please choose 1 or 0.")


if __name__ == "__main__":
    raise SystemExit(main())
