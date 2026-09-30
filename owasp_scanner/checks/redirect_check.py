"""Checks whether plain HTTP is properly redirected to HTTPS (FR-REDIR-*, FR-FIX-09).

Maps to OWASP Top 10 A02:2021 (Cryptographic Failures).
"""

from __future__ import annotations

from urllib.parse import urljoin, urlsplit

from ..http_utils import MAX_REDIRECTS, in_scope, safe_get, url_host
from ..models import Finding, Severity


def _finding(start_url: str, final_url: str) -> Finding:
    return Finding(
        id="TLS-NO-HTTPS-REDIRECT",
        title="Plain HTTP is not redirected to HTTPS",
        severity=Severity.HIGH,
        owasp_category="A02:2021 - Cryptographic Failures",
        description=f"Requesting {start_url} did not result in an HTTPS URL (final URL: {final_url}).",
        recommendation="Redirect all HTTP traffic to HTTPS (301) at the web server/load balancer.",
        url=start_url,
        instance_key=start_url,
    )


def _is_https(url: str) -> bool:
    return url.lower().startswith("https://")


def check_http_to_https_redirect(session, hostname: str) -> list[Finding]:
    """Target entered as https://: probe ``http://<hostname>/`` hop by hop.

    The check never loads an HTTPS page: a redirect pointing at ``https://`` is the
    answer. That keeps certificate problems (reported by the TLS check) from being
    mistaken for a missing redirect.
    """
    start = f"http://{url_host(hostname)}/"
    scope = getattr(session, "scope_host", None) or urlsplit(start).hostname or hostname
    url = start
    for _ in range(MAX_REDIRECTS):
        resp, err = safe_get(session, url, allow_redirects=False)
        if err or resp is None:
            return []  # FR-REDIR-02: plain HTTP not reachable at all is not a finding
        location = resp.headers.get("Location") if resp.is_redirect else None
        if not location:
            return [_finding(start, url)]
        next_url = urljoin(url, location)
        if _is_https(next_url):
            return []
        if not in_scope(next_url, scope):
            if hasattr(session, "note_blocked"):
                session.note_blocked(next_url, url)
            return []  # D4: do not follow; no verdict
        url = next_url
    return []  # too many hops: no verdict


def evaluate_redirect_chain(start_url: str, chain: list[str]) -> list[Finding]:
    """Target entered as http://: judge from the baseline's own redirect chain (no extra request)."""
    if any(_is_https(url) for url in chain):
        return []
    return [_finding(start_url, chain[-1] if chain else start_url)]
