"""Cookie attribute checks (Secure / HttpOnly / SameSite).

Maps to OWASP ASVS V3 (Session Management) and Top 10 A05/A07.
"""
from __future__ import annotations

from http.cookies import SimpleCookie

from ..models import Finding, Severity


def check_cookies(url: str, set_cookie_headers: list[str]) -> list[Finding]:
    findings: list[Finding] = []

    for raw in set_cookie_headers:
        cookie = SimpleCookie()
        try:
            cookie.load(raw)
        except Exception:
            continue

        for name, morsel in cookie.items():
            missing = []
            if not morsel["secure"]:
                missing.append("Secure")
            if not morsel["httponly"]:
                missing.append("HttpOnly")
            samesite = morsel.get("samesite", "")
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
                    )
                )

    return findings
