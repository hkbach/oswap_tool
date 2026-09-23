"""CORS misconfiguration check.

Sends an ordinary GET with a benign, clearly-marked test Origin header
(no payload) and inspects how the server echoes CORS headers back.
Maps to OWASP Top 10 A05:2021 (also touches A01 - Broken Access Control
when combined with credentialed requests).
"""
from __future__ import annotations

from ..http_utils import safe_get
from ..models import Finding, Severity

_TEST_ORIGIN = "https://owasp-scanner-cors-test.invalid"


def check_cors(session, url: str) -> list[Finding]:
    findings: list[Finding] = []
    resp, err = safe_get(session, url, headers={"Origin": _TEST_ORIGIN})
    if err or resp is None:
        return findings

    acao = resp.headers.get("Access-Control-Allow-Origin")
    acac = resp.headers.get("Access-Control-Allow-Credentials", "").lower() == "true"

    if acao == "*" and acac:
        findings.append(
            Finding(
                id="CORS-WILDCARD-WITH-CREDENTIALS",
                title="CORS allows '*' origin together with credentials",
                severity=Severity.CRITICAL,
                owasp_category="A05:2021 - Security Misconfiguration",
                description=(
                    "Browsers forbid this combination, but seeing both headers together "
                    "usually indicates copy-pasted/misconfigured CORS middleware."
                ),
                evidence="Access-Control-Allow-Origin: *, Access-Control-Allow-Credentials: true",
                url=url,
            )
        )
    elif acao == _TEST_ORIGIN:
        findings.append(
            Finding(
                id="CORS-REFLECTS-ARBITRARY-ORIGIN",
                title="CORS reflects an arbitrary, unrecognized Origin",
                severity=Severity.HIGH if acac else Severity.MEDIUM,
                owasp_category="A05:2021 - Security Misconfiguration",
                description=(
                    "The server echoed back a made-up test Origin in "
                    "Access-Control-Allow-Origin"
                    + (" with credentials allowed, letting any site read authenticated responses."
                       if acac else ".")
                ),
                evidence=f"Origin sent: {_TEST_ORIGIN} -> Access-Control-Allow-Origin: {acao}",
                recommendation="Validate Origin against an explicit allow-list server-side; never reflect it verbatim.",
                url=url,
            )
        )
    elif acao == "*":
        findings.append(
            Finding(
                id="CORS-WILDCARD",
                title="CORS allows any origin ('*')",
                severity=Severity.INFO,
                owasp_category="A05:2021 - Security Misconfiguration",
                description="Access-Control-Allow-Origin is '*'. Fine for public, non-authenticated APIs; risky otherwise.",
                recommendation="Confirm this endpoint truly serves only public, non-sensitive data.",
                url=url,
            )
        )

    return findings
