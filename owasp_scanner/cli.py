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
from urllib.parse import urlparse, urlsplit, urlunsplit

import requests

from .checks import cookies, cors_check, exposure, headers, redirect_check, tls_check
from .http_utils import build_session
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
    # urlparse() reads "host:port" as scheme "host", so test for "://" instead.
    if "://" not in target:
        target = "https://" + target
    parts = urlsplit(target)
    path = parts.path if parts.path.endswith("/") else parts.path + "/"
    return urlunsplit(parts._replace(path=path))


def _utc_timestamp() -> str:
    return datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None).isoformat() + "Z"


def _fetch_baseline(session, url: str):
    """GET that never raises; returns (response, error_str, failed_in_tls_layer)."""
    try:
        return session.get(url), None, False
    except requests.exceptions.SSLError as exc:
        return None, str(exc), True
    except requests.exceptions.RequestException as exc:
        return None, str(exc), False


def _run_check(result: ScanResult, name: str, check, *args, **kwargs) -> None:
    result.checks_run.append(name)
    try:
        for f in check(*args, **kwargs):
            result.add(f)
    except Exception as exc:  # one broken check must not abort the scan (FR-REPORT-05)
        result.errors.append(f"Check '{name}' failed: {exc!r}")


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

    result = ScanResult(target=base_url, started_at=_utc_timestamp())
    session = build_session(timeout=timeout)
    tls_args = (tls_check.check_tls, hostname)
    tls_kwargs = {"port": parsed.port or 443, "timeout": timeout}

    # 1. Baseline fetch of the target page
    resp, err, tls_failure = _fetch_baseline(session, base_url)
    if err or resp is None:
        result.errors.append(f"Could not fetch {base_url}: {err}")
        # An expired/untrusted certificate makes the verifying baseline GET fail;
        # the TLS check opens its own connections and is exactly what explains it.
        if tls_failure:
            _run_check(result, "tls", *tls_args, **tls_kwargs)
        result.finished_at = _utc_timestamp()
        return result

    _run_check(
        result, "security-headers", headers.check_security_headers,
        base_url, dict(resp.headers), is_https=(parsed.scheme == "https"),
    )

    # requests folds repeated Set-Cookie headers into one string, so read them from
    # the raw urllib3 headers — of the final response and of every redirect hop.
    set_cookie_headers = [raw for r in (*resp.history, resp) for raw in r.raw.headers.getlist("Set-Cookie")]
    _run_check(result, "cookies", cookies.check_cookies, base_url, set_cookie_headers)

    if parsed.scheme == "https":
        _run_check(result, "tls", *tls_args, **tls_kwargs)
        _run_check(result, "http-to-https-redirect", redirect_check.check_http_to_https_redirect, session, hostname)

    _run_check(result, "cors", cors_check.check_cors, session, base_url)
    _run_check(result, "sensitive-paths", exposure.check_sensitive_paths, session, base_url, max_workers=workers)
    _run_check(result, "directory-listing", exposure.check_directory_listing, session, base_url)
    _run_check(result, "robots-sitemap", exposure.check_robots_and_sitemap, session, base_url)

    result.finished_at = _utc_timestamp()
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
