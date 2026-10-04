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
import hashlib
import os
import re
import ssl
import sys
from collections.abc import Iterable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from urllib.parse import urlparse, urlsplit, urlunsplit

import requests

from . import __version__, catalog, request_options
from .baseline import Baseline, BaselineError, load_baseline
from .catalog import enrich
from .checks import cookies, cors_check, exposure, headers, redirect_check, tls_check
from .config import CONFIG_KEYS, ConfigError, load_config
from .exports import to_csv, to_junit
from .html_report import render_html
from .http_utils import build_session, excluded
from .limits import ScanLimiter, ScanLimitReached
from .models import ScanResult
from .output import DEFAULT_FAIL_ON, FAIL_ON_CHOICES, build_report, exit_code, gate_message, scrub_text
from .redact import redact
from .report import print_report, write_json
from .rule_loader import load_exclusions
from .sarif import to_sarif
from .soft404 import build_profile
from .suppressions import SuppressionError, Suppressions, load_suppressions

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
    """``example.com`` -> ``https://example.com/``. Raises ValueError on a target we cannot scan.

    The Web UI applies the same rule before accepting a scan (FR-UI-04), so both entry points
    reject the same targets instead of the CLI running an empty scan and reporting a confusing
    connection error.
    """
    target = target.strip()
    if not target:
        raise ValueError("the target is empty")
    # urlparse() reads "host:port" as scheme "host", so test for "://" instead. A scheme with
    # no "//" (javascript:, data:, mailto:) must still be refused rather than turned into
    # "https://javascript:alert(1)/"; what follows the colon tells the two apart, because a
    # port is all digits.
    if "://" not in target:
        prefix = re.match(r"^([A-Za-z][A-Za-z0-9+.\-]*):(.*)$", target)
        if prefix and not prefix.group(2).split("/")[0].isdigit():
            raise ValueError(f"{target!r}: only http:// and https:// targets can be scanned")
        target = "https://" + target
    parts = urlsplit(target)
    if parts.scheme.lower() not in ("http", "https"):
        raise ValueError(f"{target!r}: only http:// and https:// targets can be scanned")
    if not parts.hostname:
        raise ValueError(f"{target!r}: no hostname, expected something like https://example.com")
    path = parts.path if parts.path.endswith("/") else parts.path + "/"
    return urlunsplit(parts._replace(path=path))


def _utc_timestamp() -> str:
    return datetime.datetime.now(datetime.UTC).replace(tzinfo=None).isoformat() + "Z"


def _fetch_baseline(session, url: str):
    """GET that never raises; returns (response, error_str, tls_error_url).

    ``tls_error_url`` is the URL whose TLS handshake failed — after an http -> https
    redirect that is the HTTPS hop, not the URL we started from.
    """
    if excluded(session, url):
        # FR-AUTHZ-06 / SRS FR-EXCL-02: every request goes through safe_get()/get_limited(), which honour
        # the exclusions; this one used to bypass them. The built-in list is exactly the paths
        # where one GET can log a session out, delete something or start a checkout, so a
        # target that lands on such a path must not be fetched either. No request is sent and
        # the scan reports itself incomplete (exit code 3) rather than looking clean.
        return None, "it is excluded by this scan's own configuration (--exclude/--exclude-host)", None
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
    except ScanLimitReached:
        raise  # a reached limit stops the whole scan, it is not a broken check
    except Exception as exc:  # one broken check must not abort the scan (FR-REPORT-05)
        result.errors.append(f"Check '{name}' failed: {exc!r}")


def _positive_float(value: str) -> float:
    """argparse type for --rate-limit / --max-duration."""
    try:
        number = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"{value!r} is not a number") from exc
    if number <= 0:
        raise argparse.ArgumentTypeError(f"must be greater than 0, got {number:g}")
    return number


def _positive_int(value: str) -> int:
    """argparse type for --max-requests."""
    try:
        number = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"{value!r} is not a whole number") from exc
    if number <= 0:
        raise argparse.ArgumentTypeError(f"must be greater than 0, got {number}")
    return number


def _regex(value: str) -> str:
    """argparse type for --exclude: validate here so a typo fails before any request."""
    try:
        re.compile(value)
    except re.error as exc:
        raise argparse.ArgumentTypeError(f"invalid regular expression {value!r}: {exc}") from exc
    return value


def _as_type(parse):
    """Turn a request_options parser into an argparse type."""

    def convert(value: str):
        try:
            return parse(value)
        except ValueError as exc:
            raise argparse.ArgumentTypeError(str(exc)) from exc

    convert.__name__ = parse.__name__
    return convert


def _baseline(value: str) -> Baseline:
    """argparse type for --baseline: load it now, so a bad file fails before any request."""
    try:
        return load_baseline(value)
    except BaselineError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc


def _suppressions(value: str) -> Suppressions:
    """argparse type for --suppressions: same reasoning as --baseline."""
    try:
        return load_suppressions(value)
    except SuppressionError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc


def _ca_bundle(value: str) -> str:
    """argparse type for --ca-bundle: an existing file that OpenSSL can load."""
    try:
        ssl.create_default_context(cafile=value)
    except (OSError, ssl.SSLError) as exc:
        raise argparse.ArgumentTypeError(f"cannot load CA bundle {value!r}: {exc}") from exc
    return value


def _confirm_authorization(assume_yes: bool, quiet: bool = False) -> bool:
    # --quiet drops the banner only when the operator has already confirmed with --yes;
    # an interactive confirmation always shows what is being agreed to.
    if not (quiet and assume_yes):
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
    rate_limit: float | None = None,
    max_requests: int | None = None,
    max_duration: float | None = None,
    scope_hosts: Iterable[str] = (),
    exclude: Iterable[str] = (),
    exclude_hosts: Iterable[str] = (),
    default_excludes: bool = True,
    send_scan_id: bool = False,
    extra_headers: dict[str, str] | None = None,
    extra_cookies: dict[str, str] | None = None,
    proxy: str | None = None,
    user_agent_prefix: str | None = None,
    on_request=None,
) -> ScanResult:
    """Scan ``base_url``. ``groups`` selects check groups (catalog.GROUP_IDS); None means all.

    The baseline GET always runs; a group that is not selected sends no request of its own.
    """
    parsed = urlparse(base_url)
    hostname = parsed.hostname or base_url
    selected = catalog.normalize_groups(groups) if groups is not None else list(catalog.GROUP_IDS)

    result = ScanResult(target=base_url, started_at=_utc_timestamp(), scan_groups=selected)
    want = set(selected).__contains__
    limiter = ScanLimiter(rate_limit=rate_limit, max_requests=max_requests, max_duration=max_duration)
    exclusions = list(load_exclusions().patterns) if default_excludes else []
    exclusions += [re.compile(pattern, re.IGNORECASE) for pattern in exclude]
    session = build_session(
        timeout=timeout,
        scope_host=hostname,
        ca_bundle=ca_bundle,
        limiter=limiter,
        allowed_hosts=scope_hosts,
        exclusions=exclusions,
        excluded_hosts=exclude_hosts,
        scan_id=result.scan_id if send_scan_id else None,
        user_agent=request_options.user_agent(user_agent_prefix),
        extra_headers=extra_headers,
        cookies=extra_cookies,
        proxy=proxy,
        on_request=on_request,
    )

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
            limiter=limiter,  # TLS opens its own sockets, so it needs the limiter explicitly
            proxy=proxy,  # ...and the proxy, so it does not connect directly (FR-CI-07)
        )

    try:
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
                _run_check(
                    result, "http-to-https-redirect", redirect_check.check_http_to_https_redirect, session, hostname
                )
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

    except ScanLimitReached as exc:
        # A cap was hit: stop here rather than let every remaining check hit it too.
        result.errors.append(f"Scan stopped early: {exc}")
    finally:
        result.errors.extend(session.blocked_redirects.values())
        if session.excluded_urls:
            result.errors.append(
                f"{len(session.excluded_urls)} URL(s) were not requested because they are excluded "
                f"(FR-AUTHZ-06): {', '.join(sorted(session.excluded_urls)[:5])}"
                + (" ..." if len(session.excluded_urls) > 5 else "")
            )
        result.limits = limiter.snapshot()
        result.finished_at = _utc_timestamp()
    return result


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="websec-scanner",
        description="Non-intrusive web security configuration scanner (headers, TLS, cookies, CORS, exposure).",
    )
    parser.add_argument(
        "target", nargs="*", help="Target URL(s) or hostname(s), e.g. https://example.com (several allowed)"
    )
    parser.add_argument("--config", metavar="FILE", help="TOML file with any of these options; the command line wins")
    multi = parser.add_argument_group("several targets (FR-CI-05)")
    multi.add_argument("--targets-file", metavar="FILE", help="File with one target per line ('#' starts a comment)")
    multi.add_argument(
        "--output-dir",
        metavar="DIR",
        help="Write one set of reports per target into DIR, named after the target (see --formats)",
    )
    multi.add_argument(
        "--formats",
        type=_formats,
        default=["json"],
        metavar="LIST",
        help=f"With --output-dir: comma-separated formats to write (default: json; any of {', '.join(_FORMATS)})",
    )
    multi.add_argument(
        "--baseline-dir",
        metavar="DIR",
        help="Previous --output-dir: each target is compared with its own report there (like --baseline)",
    )
    multi.add_argument(
        "--parallel",
        type=_parallel,
        default=1,
        metavar="N",
        help="Scan up to N targets at the same time (default: 1, one after another; at most 64)",
    )
    parser.add_argument("--json", metavar="PATH", help="Write full JSON report to PATH")
    parser.add_argument("--sarif", metavar="PATH", help="Write a SARIF 2.1.0 report to PATH (e.g. for code scanning)")
    parser.add_argument("--html", metavar="PATH", help="Write a standalone HTML report to PATH")
    parser.add_argument("--csv", metavar="PATH", help="Write the findings as CSV to PATH")
    parser.add_argument(
        "--junit", metavar="PATH", help="Write a JUnit XML report to PATH (fails exactly when the exit code is not 0)"
    )
    history = parser.add_argument_group("compare with earlier scans (FR-CI-02, FR-MODEL-06)")
    history.add_argument(
        "--baseline",
        type=_baseline,
        metavar="FILE",
        help="JSON report of a previous scan: only findings new since then fail the gate",
    )
    history.add_argument(
        "--suppressions",
        type=_suppressions,
        metavar="FILE",
        help="TOML file of accepted findings, each with a reason and an expiry date (e.g. .scannerignore.toml)",
    )
    parser.add_argument("--timeout", type=int, default=10, help="Per-request timeout in seconds (default: 10)")
    parser.add_argument("--workers", type=int, default=5, help="Concurrent requests for path checks (default: 5)")
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI colors in CLI output")
    parser.add_argument("--version", action="version", version=f"websec-scanner {__version__}")
    verbosity = parser.add_mutually_exclusive_group()
    verbosity.add_argument("--quiet", action="store_true", help="Print one summary line per target")
    verbosity.add_argument(
        "--verbose", action="store_true", help="Also log every request sent, to stderr (credentials masked)"
    )
    requests_group = parser.add_argument_group("request options (FR-CI-07)")
    requests_group.add_argument(
        "--header",
        action="append",
        default=[],
        type=_as_type(request_options.parse_header),
        metavar="'NAME: VALUE'",
        help="Extra request header (repeatable). Credential headers are masked in every report",
    )
    requests_group.add_argument(
        "--cookie",
        action="append",
        default=[],
        type=_as_type(request_options.parse_cookie),
        metavar="NAME=VALUE",
        help="Cookie to send (repeatable). Values are masked in every report",
    )
    requests_group.add_argument(
        "--proxy",
        type=_as_type(request_options.validate_proxy),
        metavar="URL",
        help="http:// proxy for every request, the TLS check included (http://[user:pass@]host:port)",
    )
    requests_group.add_argument(
        "--user-agent",
        type=_as_type(request_options.user_agent_prefix),
        metavar="PREFIX",
        help="Text put in front of the scanner's User-Agent; it never replaces it (NFR-SEC-03)",
    )
    limits = parser.add_argument_group("scan limits (FR-AUTHZ-05; no limit unless set)")
    limits.add_argument("--rate-limit", type=_positive_float, metavar="N", help="Send at most N requests per second")
    limits.add_argument("--max-requests", type=_positive_int, metavar="N", help="Stop the scan after N requests")
    limits.add_argument("--max-duration", type=_positive_float, metavar="SECONDS", help="Stop the scan after SECONDS")
    scope = parser.add_argument_group("scope and exclusions (FR-AUTHZ-03, FR-AUTHZ-06)")
    scope.add_argument(
        "--scope-host",
        action="append",
        default=[],
        metavar="HOST",
        help="Additional host that counts as in scope (repeatable)",
    )
    scope.add_argument(
        "--exclude",
        action="append",
        default=[],
        type=_regex,
        metavar="REGEX",
        help="Never request URLs whose path matches REGEX (repeatable)",
    )
    scope.add_argument(
        "--exclude-host",
        action="append",
        default=[],
        metavar="HOST",
        help="Never request this host (repeatable)",
    )
    scope.add_argument(
        "--no-default-excludes",
        action="store_true",
        help="Drop the built-in exclusions (logout, delete, checkout; see rules/exclusions.json)",
    )
    scope.add_argument(
        "--scan-id-header",
        action="store_true",
        help="Send X-Scanner-Scan-Id so the target can filter this scan out of its logs",
    )
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
    return parser


_FORMATS = ("json", "sarif", "html", "csv", "junit")
_EXTENSIONS = {"json": "json", "sarif": "sarif", "html": "html", "csv": "csv", "junit": "xml"}
_SINGLE_FILE_OPTIONS = ("json", "sarif", "html", "csv", "junit")
_MAX_PARALLEL = 64


def _formats(value: str) -> list[str]:
    """argparse type for --formats."""
    wanted = [item.strip().lower() for item in value.split(",") if item.strip()]
    unknown = sorted(set(wanted) - set(_FORMATS))
    if unknown or not wanted:
        raise argparse.ArgumentTypeError(f"unknown format(s) {unknown}; choose from {', '.join(_FORMATS)}")
    return [f for f in _FORMATS if f in wanted]


def _parallel(value: str) -> int:
    """argparse type for --parallel: a bounded number, so a typo cannot start hundreds of scans."""
    number = _positive_int(value)
    if number > _MAX_PARALLEL:
        raise argparse.ArgumentTypeError(f"at most {_MAX_PARALLEL} targets at a time, got {number}")
    return number


def _apply_config(parser: argparse.ArgumentParser, argv) -> None:
    """FR-CI-06: load --config into the parser's defaults, so the command line still wins."""
    pre = argparse.ArgumentParser(add_help=False)
    pre.add_argument("--config")
    known, _ = pre.parse_known_args(argv)
    if not known.config:
        return
    try:
        values, warnings = load_config(known.config)
    except ConfigError as exc:
        parser.error(str(exc))
    for warning in warnings:
        print(f"WARNING: {warning}", file=sys.stderr)

    def convert(key: str, raw):
        """Run a config value through the same validation as its command-line option."""
        try:
            if key == "headers":
                return [request_options.parse_header(f"{name}: {value}") for name, value in raw.items()]
            if key == "cookies":
                return [request_options.parse_cookie(f"{name}={value}") for name, value in raw.items()]
            if key == "checks":
                return _check_groups(",".join(raw))
            if key == "formats":
                return _formats(",".join(raw))
            if key == "exclude":
                return [_regex(pattern) for pattern in raw]
            if key in ("default_excludes", "color"):
                return not raw  # stored as --no-default-excludes / --no-color
            if key == "proxy":
                return request_options.validate_proxy(raw)
            if key == "user_agent":
                return request_options.user_agent_prefix(raw)
            if key in ("rate_limit", "max_duration"):
                return _positive_float(str(raw))
            if key == "max_requests":
                return _positive_int(str(raw))
            if key == "parallel":
                return _parallel(str(raw))
            if key == "fail_on" and raw not in FAIL_ON_CHOICES:
                raise ValueError(f"must be one of {', '.join(FAIL_ON_CHOICES)}")
            if key == "baseline":
                return _baseline(raw)
            if key == "suppressions":
                return _suppressions(raw)
            if key == "ca_bundle":
                return _ca_bundle(raw)
            return raw
        except (ValueError, argparse.ArgumentTypeError) as exc:
            parser.error(f"{known.config}: '{key}': {exc}")

    parser.set_defaults(**{CONFIG_KEYS[key]: convert(key, raw) for key, raw in values.items()})


def _collect_targets(parser: argparse.ArgumentParser, args) -> list[str]:
    """Positional targets and --targets-file, normalised, in order, without duplicates."""
    raw: list[tuple[str, str | None]] = [(entry, None) for entry in (args.target or [])]
    if args.targets_file:
        try:
            with open(args.targets_file, encoding="utf-8") as fh:
                lines = fh.read().splitlines()
        except OSError as exc:
            parser.error(f"cannot read --targets-file {args.targets_file!r}: {exc.strerror or exc}")
        for line in lines:
            entry = line.split("#", 1)[0].strip()
            if entry:
                raw.append((entry, args.targets_file))
    seen, targets = set(), []
    for entry, source in raw:
        try:
            target = _normalize_target(entry)
        except ValueError as exc:
            parser.error(f"{source}: {exc}" if source else str(exc))
        if target not in seen:
            seen.add(target)
            targets.append(target)
    return targets


def _report_name(target: str) -> str:
    """File name stem for one target: readable, and the same on every run (--baseline-dir relies on it)."""
    parts = urlsplit(target)
    host = (parts.hostname or "target").replace(":", "-")  # IPv6 has no place in a file name
    port = parts.port or {"http": 80, "https": 443}.get(parts.scheme, 0)
    digest = hashlib.sha256(target.encode("utf-8")).hexdigest()[:8]
    return f"{host}_{port}-{digest}"


def _check_run_options(parser: argparse.ArgumentParser, args, targets: list[str], headers, cookies) -> None:
    """Refuse combinations that would silently do the wrong thing, before any request is sent."""
    single_files = [f"--{name}" for name in _SINGLE_FILE_OPTIONS if getattr(args, name)]
    if args.output_dir and single_files:
        parser.error(f"use either --output-dir (with --formats) or {', '.join(single_files)}, not both")
    if len(targets) > 1 and single_files:
        parser.error(f"{', '.join(single_files)} writes one file; with several targets use --output-dir instead")
    if args.baseline and args.baseline_dir:
        parser.error("use either --baseline or --baseline-dir, not both")
    if len(targets) > 1 and args.baseline:
        parser.error("--baseline is one target's report; with several targets use --baseline-dir")
    hosts = {(urlsplit(t).hostname or "").lower() for t in targets}
    credentials = [name for name in headers if request_options.is_sensitive_header(name)] + list(cookies)
    if len(hosts) > 1 and credentials:
        parser.error(
            f"credential(s) {', '.join(credentials)} would be sent to every target ({len(hosts)} different hosts), "
            "so one site's token would reach the others; scan each host in its own run"
        )


def _baseline_for(parser: argparse.ArgumentParser, args, target: str):
    """--baseline, or this target's own report in --baseline-dir (None when it has none yet)."""
    if args.baseline:
        return args.baseline, None
    if not args.baseline_dir:
        return None, None
    path = os.path.join(args.baseline_dir, _report_name(target) + ".json")
    if not os.path.exists(path):
        return None, f"No baseline for {target} in {args.baseline_dir}; every finding counts toward the gate"
    try:
        return load_baseline(path), None
    except BaselineError as exc:
        parser.error(str(exc))


def _write_outputs(args, target: str, report: dict, quiet: bool) -> None:
    writers = {
        "json": lambda path: write_json(report, path),
        "sarif": lambda path: write_json(to_sarif(report), path),
        "html": lambda path: _write_text(path, render_html(report)),
        "csv": lambda path: _write_text(path, to_csv(report), newline=""),
        "junit": lambda path: _write_text(path, to_junit(report)),
    }
    labels = {"json": "Full JSON", "sarif": "SARIF", "html": "HTML", "csv": "CSV", "junit": "JUnit"}
    if args.output_dir:
        os.makedirs(args.output_dir, exist_ok=True)
        jobs = [
            (fmt, os.path.join(args.output_dir, f"{_report_name(target)}.{_EXTENSIONS[fmt]}")) for fmt in args.formats
        ]
    else:
        jobs = [(fmt, getattr(args, fmt)) for fmt in _SINGLE_FILE_OPTIONS if getattr(args, fmt)]
    for fmt, path in jobs:
        writers[fmt](path)
        if not quiet:
            print(f"{labels[fmt]} report written to: {path}")


def _write_text(path: str, text: str, newline: str | None = None) -> None:
    with open(path, "w", encoding="utf-8", newline=newline) as fh:
        fh.write(text)


def _quiet_line(target: str, report: dict, code: int) -> str:
    status, _ = gate_message(report["gate"])
    return f"{target}: {len(report['findings'])} findings, gate {status} (exit {code})"


def main(argv=None) -> int:
    parser = build_parser()
    _apply_config(parser, argv)
    args = parser.parse_args(argv)
    if args.list_checks:
        for group in catalog.CHECK_GROUPS:
            print(f"{group.id:<18} {group.title}")
            print(f"{'':<18} {group.description}")
        return 0

    targets = _collect_targets(parser, args)
    if not targets:
        parser.error("the following arguments are required: target (or --targets-file, or targets in --config)")
    headers, cookies = dict(args.header), dict(args.cookie)
    _check_run_options(parser, args, targets, headers, cookies)
    baselines = {target: _baseline_for(parser, args, target) for target in targets}  # fail on a bad file now

    if not _confirm_authorization(args.assume_yes, args.quiet):
        print("Authorization not confirmed. Aborting.")
        return 2
    if args.show_secrets:
        print(
            "WARNING: --show-secrets is set: cookie values and sensitive URL parameters are NOT redacted. "
            "Do not share this output.",
            file=sys.stderr,
        )

    secrets = request_options.secrets_of(headers, cookies, args.proxy)

    def log_request(method: str, url: str, status, error) -> None:
        outcome = status if status is not None else f"error {error}"
        print(f"[request] {method} {scrub_text(url, secrets)} -> {outcome}", file=sys.stderr)

    def scan(target: str) -> ScanResult:
        return run_scan(
            target,
            timeout=args.timeout,
            workers=args.workers,
            ca_bundle=args.ca_bundle,
            groups=args.checks,
            rate_limit=args.rate_limit,
            max_requests=args.max_requests,
            max_duration=args.max_duration,
            scope_hosts=args.scope_host,
            exclude=args.exclude,
            exclude_hosts=args.exclude_host,
            default_excludes=not args.no_default_excludes,
            send_scan_id=args.scan_id_header,
            extra_headers=headers,
            extra_cookies=cookies,
            proxy=args.proxy,
            user_agent_prefix=args.user_agent,
            on_request=log_request if args.verbose else None,
        )

    def report_for(target: str, result: ScanResult) -> dict:
        baseline, note = baselines[target]
        if note:
            result.errors.append(note)
        return build_report(
            result,
            show_secrets=args.show_secrets,
            fail_on=args.fail_on,
            baseline=baseline,
            suppressions=args.suppressions,
            secrets=secrets,
        )

    def show(target: str, report: dict) -> int:
        code = exit_code(report)
        if args.quiet:
            print(_quiet_line(target, report, code))
            # Still say *why* a scan is incomplete or a check failed: an exit code with no
            # reason is useless in a CI log. stderr, so stdout stays one line per target.
            for error in report["errors"]:
                print(f"{target}: {error}", file=sys.stderr)
        else:
            print_report(report, use_color=not args.no_color)
            print()
        _write_outputs(args, target, report, args.quiet)
        return code

    codes: list[int] = []
    summary: list[tuple[str, dict, int]] = []
    if args.parallel == 1 or len(targets) == 1:
        for target in targets:  # one after another: each report as soon as its scan ends
            if not args.quiet:
                print(f"Scanning {target if args.show_secrets else redact(target)} ...\n")
            report = report_for(target, scan(target))
            codes.append(show(target, report))
            summary.append((target, report, codes[-1]))
    else:
        if not args.quiet:
            print(f"Scanning {len(targets)} targets, up to {args.parallel} at a time ...\n")
        with ThreadPoolExecutor(max_workers=args.parallel) as pool:
            results = list(pool.map(scan, targets))  # map keeps input order
        for target, result in zip(targets, results, strict=True):
            report = report_for(target, result)
            codes.append(show(target, report))
            summary.append((target, report, codes[-1]))

    if len(targets) > 1 and not args.quiet:
        print("=" * 72)
        print(f" Summary of {len(targets)} targets:")
        for target, report, code in summary:
            status, _ = gate_message(report["gate"])
            print(f"  {status:<5} exit {code}  {len(report['findings']):>3} findings  {redact(target)}")
    # The worst target decides: a failing gate (1) outranks an incomplete scan (3), then a pass (0).
    return 1 if 1 in codes else 3 if 3 in codes else 0


if __name__ == "__main__":
    sys.exit(main())
