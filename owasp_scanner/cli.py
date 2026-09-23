"""Command-line entry point.

Usage:
    python -m owasp_scanner https://example.com
    python -m owasp_scanner https://example.com --json report.json --yes

IMPORTANT: only run this against systems you own or have explicit,
documented authorization to test. See README.md.
"""
from __future__ import annotations

import argparse
import datetime
import sys
from urllib.parse import urlparse

from .checks import cookies, cors_check, exposure, headers, redirect_check, tls_check
from .http_utils import build_session, safe_get
from .models import ScanResult
from .report import print_report, write_json

CONSENT_BANNER = """
==========================================================================
 OWASP-Aligned Passive Web Security Scanner
==========================================================================
 This tool sends ordinary, non-destructive HTTP GET requests to check
 security headers, TLS configuration, cookie flags, CORS behavior, and
 commonly-exposed sensitive files/paths.

 It does NOT attempt exploitation (no SQL injection payloads, no auth
 bruteforce, no fuzzing). Even so, only run it against systems you own,
 or for which you have explicit, documented authorization to test.
 Unauthorized scanning of third-party systems may be illegal in your
 jurisdiction and typically violates the target's terms of service.
==========================================================================
"""


def _normalize_target(target: str) -> str:
    if not urlparse(target).scheme:
        target = "https://" + target
    return target.rstrip("/") + "/"


def _confirm_authorization(assume_yes: bool) -> bool:
    print(CONSENT_BANNER)
    if assume_yes:
        return True
    try:
        answer = input("Do you own this target or have written authorization to scan it? [yes/NO]: ")
    except EOFError:
        return False
    return answer.strip().lower() in ("y", "yes")


def run_scan(base_url: str, timeout: int = 10, workers: int = 5) -> ScanResult:
    parsed = urlparse(base_url)
    hostname = parsed.hostname or base_url

    result = ScanResult(target=base_url, started_at=datetime.datetime.utcnow().isoformat() + "Z")
    session = build_session(timeout=timeout)

    # 1. Baseline fetch of the target page
    resp, err = safe_get(session, base_url)
    if err or resp is None:
        result.errors.append(f"Could not fetch {base_url}: {err}")
        result.finished_at = datetime.datetime.utcnow().isoformat() + "Z"
        return result

    result.checks_run.append("security-headers")
    for f in headers.check_security_headers(base_url, dict(resp.headers), is_https=(parsed.scheme == "https")):
        result.add(f)

    result.checks_run.append("cookies")
    set_cookie_headers = resp.raw.headers.get_all("Set-Cookie") if hasattr(resp.raw, "headers") else None
    if not set_cookie_headers:
        # requests folds multiple Set-Cookie headers; fall back to the cookie jar
        set_cookie_headers = [f"{c.name}={c.value}" for c in resp.cookies]
    for f in cookies.check_cookies(base_url, set_cookie_headers or []):
        result.add(f)

    if parsed.scheme == "https":
        result.checks_run.append("tls")
        for f in tls_check.check_tls(hostname, port=parsed.port or 443, timeout=timeout):
            result.add(f)

        result.checks_run.append("http-to-https-redirect")
        for f in redirect_check.check_http_to_https_redirect(session, hostname):
            result.add(f)

    result.checks_run.append("cors")
    for f in cors_check.check_cors(session, base_url):
        result.add(f)

    result.checks_run.append("sensitive-paths")
    for f in exposure.check_sensitive_paths(session, base_url, max_workers=workers):
        result.add(f)

    result.checks_run.append("directory-listing")
    for f in exposure.check_directory_listing(session, base_url):
        result.add(f)

    result.checks_run.append("robots-sitemap")
    for f in exposure.check_robots_and_sitemap(session, base_url):
        result.add(f)

    result.finished_at = datetime.datetime.utcnow().isoformat() + "Z"
    return result


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="owasp-scanner",
        description="OWASP-aligned passive web security scanner (headers, TLS, cookies, CORS, exposure).",
    )
    parser.add_argument("target", help="Target URL or hostname, e.g. https://example.com")
    parser.add_argument("--json", metavar="PATH", help="Write full JSON report to PATH")
    parser.add_argument("--timeout", type=int, default=10, help="Per-request timeout in seconds (default: 10)")
    parser.add_argument("--workers", type=int, default=5, help="Concurrent requests for path checks (default: 5)")
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI colors in CLI output")
    parser.add_argument(
        "--yes",
        "--i-have-authorization",
        dest="assume_yes",
        action="store_true",
        help="Skip the interactive authorization confirmation (use in CI with care).",
    )
    args = parser.parse_args(argv)

    if not _confirm_authorization(args.assume_yes):
        print("Authorization not confirmed. Aborting.")
        return 2

    target = _normalize_target(args.target)
    print(f"Scanning {target} ...\n")

    result = run_scan(target, timeout=args.timeout, workers=args.workers)
    print_report(result, use_color=not args.no_color)

    if args.json:
        write_json(result, args.json)
        print(f"\nFull JSON report written to: {args.json}")

    counts = result.summary_counts()
    if counts["CRITICAL"] or counts["HIGH"]:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
