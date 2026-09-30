"""Checks whether plain HTTP is properly redirected to HTTPS.

Maps to OWASP Top 10 A02:2021 (Cryptographic Failures).
"""
from __future__ import annotations

from ..http_utils import safe_get
from ..models import Finding, Severity


def check_http_to_https_redirect(session, hostname: str) -> list[Finding]:
    findings: list[Finding] = []
    http_url = f"http://{hostname}/"

    resp, err = safe_get(session, http_url, allow_redirects=True)
    if err or resp is None:
        # Plain HTTP not reachable at all is not a finding in itself.
        return findings

    final_url = resp.url
    if not final_url.startswith("https://"):
        findings.append(
            Finding(
                id="TLS-NO-HTTPS-REDIRECT",
                title="Plain HTTP is not redirected to HTTPS",
                severity=Severity.HIGH,
                owasp_category="A02:2021 - Cryptographic Failures",
                description=f"Requesting {http_url} did not result in an HTTPS URL (final URL: {final_url}).",
                recommendation="Redirect all HTTP traffic to HTTPS (301) at the web server/load balancer.",
                url=http_url,
            )
        )

    return findings
