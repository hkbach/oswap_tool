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
                # D3: MEDIUM, not CRITICAL - not directly exploitable from a browser.
                severity=Severity.MEDIUM,
                owasp_category="A05:2021 - Security Misconfiguration",
                description=(
                    "Browsers refuse credentialed requests when Access-Control-Allow-Origin is '*', so this "
                    "pair is not directly exploitable from a browser. It does show copy-pasted or misconfigured "
                    "CORS middleware, and non-browser clients may still honour it, so the whole policy needs review."
                ),
                evidence="Access-Control-Allow-Origin: *, Access-Control-Allow-Credentials: true",
                recommendation=(
                    "Decide whether this endpoint needs credentials. If it does, allow-list the trusted origins "
                    "explicitly; if it does not, drop Access-Control-Allow-Credentials."
                ),
                url=url,
                instance_key=url,
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
                    "The server echoed back a made-up test Origin in Access-Control-Allow-Origin"
                    + (
                        " with Access-Control-Allow-Credentials: true, so any website a logged-in user visits "
                        "can read that user's authenticated responses."
                        if acac
                        else " without credentials, so any website can read the unauthenticated responses; "
                        "the risk grows if credentials are ever enabled."
                    )
                ),
                evidence=f"Origin sent: {_TEST_ORIGIN} -> Access-Control-Allow-Origin: {acao}",
                recommendation="Validate Origin against an explicit allow-list server-side; never reflect it verbatim.",
                url=url,
                instance_key=url,
            )
        )
    elif acao == "*":
        findings.append(
            Finding(
                id="CORS-WILDCARD",
                title="CORS allows any origin ('*')",
                severity=Severity.INFO,
                owasp_category="A05:2021 - Security Misconfiguration",
                description=(
                    "Access-Control-Allow-Origin is '*' without credentials: acceptable for public, "
                    "non-authenticated APIs, risky if the endpoint returns private data."
                ),
                recommendation="Confirm this endpoint truly serves only public, non-sensitive data.",
                url=url,
                instance_key=url,
            )
        )

    return findings
