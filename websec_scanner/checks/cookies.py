"""Cookie attribute checks (Secure / HttpOnly / SameSite).

Maps to OWASP ASVS V3 (Session Management) and Top 10 A05/A07.
"""

from __future__ import annotations

import re

from ..catalog import CVSS_COOKIE_READABLE_BY_SCRIPT, CVSS_COOKIE_SENT_CROSS_SITE
from ..models import Finding, Severity
from ..redact import cookie_redaction

# CWE for the most important missing attribute (they are listed Secure, HttpOnly, SameSite).
_CWE_BY_ATTRIBUTE = {"Secure": "CWE-614", "HttpOnly": "CWE-1004", "SameSite": "CWE-1275"}
# Same order: a cookie without Secure is the catalog's worst case, so it keeps the catalog
# vector; the other two are milder and override it per cookie (FR-MODEL-03).
_CVSS_BY_ATTRIBUTE = {"Secure": "", "HttpOnly": CVSS_COOKIE_READABLE_BY_SCRIPT, "SameSite": CVSS_COOKIE_SENT_CROSS_SITE}
# RFC 6265 cookie-name (an HTTP token).
_COOKIE_NAME = re.compile(r"[!#$%&'*+\-.^_`|~0-9A-Za-z]+")


def _parse_set_cookie(raw: str) -> tuple[str, dict[str, str]] | None:
    """Cookie name and lower-cased attributes of one Set-Cookie header, as a browser reads it.

    The first ``name=value`` pair is the cookie; everything after it is an attribute, so
    attributes the scanner does not check (Priority, Partitioned, ...) are simply ignored.
    """
    pair, *attributes = raw.split(";")
    name, sep, _value = pair.partition("=")
    name = name.strip()
    if not sep or not _COOKIE_NAME.fullmatch(name):
        return None
    parsed: dict[str, str] = {}
    for attribute in attributes:
        key, _, value = attribute.partition("=")
        parsed[key.strip().lower()] = value.strip()  # RFC 6265: a repeated attribute, the last wins
    return name, parsed


def check_cookies(url: str, set_cookie_headers: list[str]) -> list[Finding]:
    findings: list[Finding] = []

    for raw in set_cookie_headers:
        cookie = _parse_set_cookie(raw)
        if cookie is None:  # no valid name=value pair: nothing to evaluate
            continue
        name, attributes = cookie

        missing = []
        if "secure" not in attributes:
            missing.append("Secure")
        if "httponly" not in attributes:
            missing.append("HttpOnly")
        samesite = attributes.get("samesite", "")
        if not samesite:
            missing.append("SameSite")
        elif samesite.lower() not in ("lax", "strict", "none"):
            missing.append(f"SameSite(invalid value: {samesite})")

        if missing:
            findings.append(
                Finding(
                    id="COOKIE-FLAGS-MISSING",
                    title=f"Cookie '{name}' missing recommended attribute(s)",
                    severity=Severity.MEDIUM if "Secure" in missing or "HttpOnly" in missing else Severity.LOW,
                    owasp_category="A05:2021 - Security Misconfiguration",
                    description=f"Cookie '{name}' is missing: {', '.join(missing)}.",
                    evidence=raw,
                    recommendation=(
                        "Set Secure (HTTPS-only), HttpOnly (no JS access) and an explicit "
                        "SameSite=Lax/Strict on all session/auth cookies."
                    ),
                    url=url,
                    instance_key=name,
                    cwe=_CWE_BY_ATTRIBUTE[missing[0].split("(")[0]],
                    cvss_vector=_CVSS_BY_ATTRIBUTE[missing[0].split("(")[0]],
                    redactions=[pair] if (pair := cookie_redaction(raw)) else [],
                )
            )

    return findings
