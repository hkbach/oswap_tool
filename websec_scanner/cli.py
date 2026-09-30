"""Command-line entry point.

Usage:
    python -m websec_scanner https://example.com
    python -m websec_scanner https://example.com --json report.json --yes

IMPORTANT: only run this against systems you own or have explicit,
documented authorization to test. See README.md.
"""

from __future__ import annotations

import argparse
import datetime
import ssl
import sys
from collections.abc import Iterable
from dataclasses import replace
from urllib.parse import urlparse, urlsplit, urlunsplit

import requests

from . import catalog
from .catalog import enrich
from .checks import cookies, cors_check, exposure, headers, redirect_check, tls_check
from .html_report import render_html
from .http_utils import build_session
from .models import ScanResult
from .output import DEFAULT_FAIL_ON, FAIL_ON_CHOICES, build_report, exit_code
from .redact import redact
from .report import print_report, write_json
from .sarif import to_sarif
from .soft404 import build_profile

CONSENT_BANNER = """
==========================================================================
 Non-intrusive Web Security Scanner
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
    return datetime.datetime.now(datetime.UTC).replace(tzinfo=None).isoformat() + "Z"


def _fetch_baseline(session, url: str):
    """GET that never raises; returns (response, error_str, tls_error_url).

    ``tls_error_url`` is the URL whose TLS handshake failed — after an http -> https
    redirect that is the HTTPS hop, not the URL we started from.
    """
    try:
        return session.get(url), None, None
    except requests.exceptions.SSLError as exc:
        failed = getattr(getattr(exc, "request", None), "url", None) or url
        return None, str(exc), failed
    except requests.exceptions.RequestException as exc:
        return None, str(exc), None


def _host_port(url: str) -> tuple[str, int]:
    parts = urlparse(url)
    return parts.hostname or url, parts.port or 443


def _run_check(result: ScanResult, name: str, check, *args, **kwargs) -> None:
    result.checks_run.append(name)
    try:
        for f in check(*args, **kwargs):
            result.add(replace(enrich(f, result.target), check=name))
    except Exception as exc:  # one broken check must not abort the scan (FR-REPORT-05)
        result.errors.append(f"Check '{name}' failed: {exc!r}")


def _ca_bundle(value: str) -> str:
    """argparse type for --ca-bundle: an existing file that OpenSSL can load."""
    try:
        ssl.create_default_context(cafile=value)
    except (OSError, ssl.SSLError) as exc:
        raise argparse.ArgumentTypeError(f"cannot load CA bundle {value!r}: {exc}") from exc
    return value


def _confirm_authorization(assume_yes: bool) -> bool:
    print(CONSENT_BANNER)
    if assume_yes:
        return True
    try:
        answer = input("Do you own this target or have written authorization to scan it? [yes/NO]: ")
    except EOFError:
        return False
    return answer.strip().lower() in ("y", "yes")


def _check_groups(value: str) -> list[str]:
    """argparse type for --checks: comma-separated group ids (SRS 4.11)."""
    try:
        return catalog.normalize_groups(part for part in value.split(",") if part.strip())
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from None


def run_scan(
    base_url: str,
    timeout: int = 10,
    workers: int = 5,
    ca_bundle: str | None = None,
    groups: Iterable[str] | None = None,
) -> ScanResult:
    """Scan ``base_url``. ``groups`` selects check groups (catalog.GROUP_IDS); None means all.

    The baseline GET always runs; a group that is not selected sends no request of its own.
    """
    parsed = urlparse(base_url)
    hostname = parsed.hostname or base_url
    selected = catalog.normalize_groups(groups) if groups is not None else list(catalog.GROUP_IDS)

    result = ScanResult(target=base_url, started_at=_utc_timestamp(), scan_groups=selected)
    want = set(selected).__contains__
    session = build_session(timeout=timeout, scope_host=hostname, ca_bundle=ca_bundle)

    def run_tls(url: str) -> None:
        tls_host, tls_port = _host_port(url)
        _run_check(
            result,
            "tls",
            tls_check.check_tls,
            tls_host,
            port=tls_port,
            timeout=timeout,
            warnings=result.errors,
            trust=session.trust_context,  # same trust decision as the HTTP requests (FR-CI-10)
        )

    # 1. Baseline fetch of the target page
    resp, err, tls_error_url = _fetch_baseline(session, base_url)
    if err or resp is None:
        result.errors.append(f"Could not fetch {base_url}: {err}")
        # An expired/untrusted certificate makes the verifying baseline GET fail;
        # the TLS check opens its own connections and is exactly what explains it.
        if tls_error_url and want("tls"):
            run_tls(tls_error_url)
        if tls_error_url and want("https-redirect"):
            if parsed.scheme == "http" and tls_error_url.lower().startswith("https://"):
                # We were redirected to HTTPS; the certificate problem is the TLS check's finding (FIX-09).
                _run_check(result, "http-to-https-redirect", lambda: [])
        result.errors.extend(session.blocked_redirects.values())
        result.finished_at = _utc_timestamp()
        return result

    result.baseline_fetched = True
    # FR-FIX-10: header checks judge the page the user actually gets (the final response),
    # and HSTS is only meaningful when that response came over HTTPS.
    result.final_url = resp.url
    result.redirect_chain = [{"url": hop.url, "status": hop.status_code} for hop in resp.history]
    final_is_https = resp.url.lower().startswith("https://")
    if want("headers"):
        _run_check(
            result,
            "security-headers",
            headers.check_security_headers,
            base_url,
            dict(resp.headers),
            is_https=final_is_https,
        )
        if final_is_https and (urlparse(resp.url).hostname or "").lower() != hostname.lower():
            _run_check(result, "hsts-start-host", headers.check_start_host_hsts, session, base_url, resp.url)

    if want("cookies"):
        # requests folds repeated Set-Cookie headers into one string, so read them from
        # the raw urllib3 headers — of the final response and of every redirect hop.
        set_cookie_headers = [raw for r in (*resp.history, resp) for raw in r.raw.headers.getlist("Set-Cookie")]
        _run_check(result, "cookies", cookies.check_cookies, base_url, set_cookie_headers)

    # FIX-09: TLS runs on the first HTTPS URL of the baseline chain (the target itself,
    # or where an http:// target redirected to), and the redirect check always runs.
    chain = [r.url for r in (*resp.history, resp)]
    https_url = next((url for url in chain if url.lower().startswith("https://")), None)
    if https_url and want("tls"):
        run_tls(https_url)
    if want("https-redirect"):
        if parsed.scheme == "https":
            _run_check(result, "http-to-https-redirect", redirect_check.check_http_to_https_redirect, session, hostname)
        elif not resp.is_redirect:  # a redirect stopped by the scope guard gives no verdict
            _run_check(result, "http-to-https-redirect", redirect_check.evaluate_redirect_chain, base_url, chain)

    if want("cors"):
        _run_check(result, "cors", cors_check.check_cors, session, base_url)
    if want("exposed-files") or want("directory-listing"):
        # One soft-404 profile (2 random probes) shared by both path-based checks (FR-DET-02).
        profile = build_profile(session, base_url)
        if want("exposed-files"):
            _run_check(
                result,
                "sensitive-paths",
                exposure.check_sensitive_paths,
                session,
                base_url,
                max_workers=workers,
                soft404_profile=profile,
            )
        if want("directory-listing"):
            _run_check(
                result,
                "directory-listing",
                exposure.check_directory_listing,
                session,
                base_url,
                soft404_profile=profile,
            )
    if want("robots-sitemap"):
        _run_check(result, "robots-sitemap", exposure.check_robots_and_sitemap, session, base_url)

    result.errors.extend(session.blocked_redirects.values())
    result.finished_at = _utc_timestamp()
    return result


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="websec-scanner",
        description="Non-intrusive web security configuration scanner (headers, TLS, cookies, CORS, exposure).",
    )
    parser.add_argument("target", nargs="?", help="Target URL or hostname, e.g. https://example.com")
    parser.add_argument("--json", metavar="PATH", help="Write full JSON report to PATH")
    parser.add_argument("--sarif", metavar="PATH", help="Write a SARIF 2.1.0 report to PATH (e.g. for code scanning)")
    parser.add_argument("--html", metavar="PATH", help="Write a standalone HTML report to PATH")
    parser.add_argument("--timeout", type=int, default=10, help="Per-request timeout in seconds (default: 10)")
    parser.add_argument("--workers", type=int, default=5, help="Concurrent requests for path checks (default: 5)")
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI colors in CLI output")
    parser.add_argument(
        "--fail-on",
        choices=FAIL_ON_CHOICES,
        default=DEFAULT_FAIL_ON,
        help="Lowest severity that fails the scan with exit code 1 (default: high). "
        "Exit code 3 means the target could not be scanned; 'none' never fails.",
    )
    parser.add_argument(
        "--ca-bundle",
        metavar="PATH",
        type=_ca_bundle,
        help="PEM file of CA certificates to trust instead of the OS store, for HTTP and TLS checks "
        "(default: REQUESTS_CA_BUNDLE / SSL_CERT_FILE, else the OS store)",
    )
    parser.add_argument(
        "--checks",
        metavar="GROUPS",
        type=_check_groups,
        help="Comma-separated check groups to run (default: all). See --list-checks.",
    )
    parser.add_argument("--list-checks", action="store_true", help="List the check groups and exit")
    parser.add_argument(
        "--show-secrets",
        action="store_true",
        help="Do not redact cookie values and sensitive URL parameters (local debugging only).",
    )
    parser.add_argument(
        "--yes",
        "--i-have-authorization",
        dest="assume_yes",
        action="store_true",
        help="Skip the interactive authorization confirmation (use in CI with care).",
    )
    args = parser.parse_args(argv)
    if args.list_checks:
        for group in catalog.CHECK_GROUPS:
            print(f"{group.id:<18} {group.title}")
            print(f"{'':<18} {group.description}")
        return 0
    if args.target is None:
        parser.error("the following arguments are required: target")

    if not _confirm_authorization(args.assume_yes):
        print("Authorization not confirmed. Aborting.")
        return 2

    target = _normalize_target(args.target)
    print(f"Scanning {target if args.show_secrets else redact(target)} ...\n")

    result = run_scan(target, timeout=args.timeout, workers=args.workers, ca_bundle=args.ca_bundle, groups=args.checks)
    if args.show_secrets:
        print(
            "WARNING: --show-secrets is set: cookie values and sensitive URL parameters are NOT redacted. "
            "Do not share this output.",
            file=sys.stderr,
        )
    report = build_report(result, show_secrets=args.show_secrets, fail_on=args.fail_on)
    print_report(report, use_color=not args.no_color)

    if args.json:
        write_json(report, args.json)
        print(f"\nFull JSON report written to: {args.json}")
    if args.sarif:
        write_json(to_sarif(report), args.sarif)
        print(f"SARIF report written to: {args.sarif}")
    if args.html:
        # Same renderer as the Web UI's "Download Test result" (FR-RPT-09).
        with open(args.html, "w", encoding="utf-8") as fh:
            fh.write(render_html(report))
        print(f"HTML report written to: {args.html}")

    return exit_code(report)


if __name__ == "__main__":
    sys.exit(main())
