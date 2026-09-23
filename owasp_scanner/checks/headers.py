"""HTTP security header checks, based on the OWASP Secure Headers
Project (https://owasp.org/www-project-secure-headers/) and the
security-header portions of OWASP ASVS chapter V14 (Configuration).
"""
from __future__ import annotations

from ..models import Finding, Severity

# Each entry: header name (case-insensitive) -> (severity if missing, owasp category, guidance)
_REQUIRED_HEADERS = {
    "strict-transport-security": (
        Severity.HIGH,
        "A02:2021 - Cryptographic Failures",
        "Send 'Strict-Transport-Security: max-age=31536000; includeSubDomains' "
        "over HTTPS so browsers refuse to downgrade to plain HTTP.",
    ),
    "content-security-policy": (
        Severity.MEDIUM,
        "A05:2021 - Security Misconfiguration",
        "Define a Content-Security-Policy to restrict script/style/frame "
        "sources and reduce the impact of XSS.",
    ),
    "x-content-type-options": (
        Severity.LOW,
        "A05:2021 - Security Misconfiguration",
        "Send 'X-Content-Type-Options: nosniff' to stop MIME-type sniffing.",
    ),
    "x-frame-options": (
        Severity.MEDIUM,
        "A05:2021 - Security Misconfiguration",
        "Send 'X-Frame-Options: DENY' or 'SAMEORIGIN' (or a CSP "
        "'frame-ancestors' directive) to prevent clickjacking.",
    ),
    "referrer-policy": (
        Severity.LOW,
        "A05:2021 - Security Misconfiguration",
        "Send a 'Referrer-Policy' (e.g. 'strict-origin-when-cross-origin') "
        "to avoid leaking full URLs to third parties.",
    ),
    "permissions-policy": (
        Severity.INFO,
        "A05:2021 - Security Misconfiguration",
        "Send a 'Permissions-Policy' to explicitly disable browser features "
        "(camera, microphone, geolocation, etc.) the site does not use.",
    ),
}

# Headers whose mere presence leaks implementation detail (A05 + supports A06
# fingerprinting of outdated components).
_INFO_LEAK_HEADERS = ["server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version"]


def check_security_headers(url: str, headers: dict, is_https: bool = True) -> list[Finding]:
    findings: list[Finding] = []
    lower_headers = {k.lower(): v for k, v in headers.items()}
    csp_value = lower_headers.get("content-security-policy", "")
    has_frame_ancestors = "frame-ancestors" in csp_value.lower()

    for header, (severity, category, advice) in _REQUIRED_HEADERS.items():
        # Strict-Transport-Security is only meaningful — and only honored by
        # browsers — when delivered over HTTPS; requiring it on a plain-HTTP
        # response would be a moot/misleading finding (see redirect_check.py
        # for the separate HTTP->HTTPS redirect requirement).
        if header == "strict-transport-security" and not is_https:
            continue

        if header not in lower_headers:
            # X-Frame-Options is redundant once CSP 'frame-ancestors' is set for
            # modern browsers; don't flag it as missing in that case (kept
            # consistent with the non-standard-value case just below).
            if header == "x-frame-options" and has_frame_ancestors:
                continue
            findings.append(
                Finding(
                    id=f"HDR-{header.upper()}-MISSING",
                    title=f"Missing '{header}' response header",
                    severity=severity,
                    owasp_category=category,
                    description=f"The response did not include a '{header}' header.",
                    recommendation=advice,
                    url=url,
                )
            )
        elif header == "x-frame-options":
            value = lower_headers[header].strip().lower()
            if value not in ("deny", "sameorigin") and not has_frame_ancestors:
                findings.append(
                    Finding(
                        id="HDR-XFO-WEAK",
                        title="X-Frame-Options set to a non-standard value",
                        severity=Severity.LOW,
                        owasp_category=category,
                        description=f"X-Frame-Options value observed: '{lower_headers[header]}'.",
                        recommendation="Use 'DENY' or 'SAMEORIGIN', or migrate to CSP frame-ancestors.",
                        url=url,
                    )
                )

    # Content-Security-Policy present but unsafe directives
    if csp_value and ("unsafe-inline" in csp_value.lower() or "unsafe-eval" in csp_value.lower()):
        findings.append(
            Finding(
                id="HDR-CSP-UNSAFE",
                title="Content-Security-Policy allows 'unsafe-inline' / 'unsafe-eval'",
                severity=Severity.MEDIUM,
                owasp_category="A03:2021 - Injection",
                description="The CSP weakens XSS mitigation by permitting inline scripts/eval.",
                evidence=csp_value,
                recommendation="Remove 'unsafe-inline'/'unsafe-eval'; use nonces or hashes instead.",
                url=url,
            )
        )
    # Legacy header that should be actively disabled, not just absent
    xxp = lower_headers.get("x-xss-protection")
    if xxp and xxp.strip() not in ("0",):
        findings.append(
            Finding(
                id="HDR-XXP-LEGACY",
                title="X-XSS-Protection is enabled instead of disabled",
                severity=Severity.INFO,
                owasp_category="A05:2021 - Security Misconfiguration",
                description=(
                    "X-XSS-Protection is deprecated and can itself introduce XSS in "
                    "older browsers; modern guidance is to send 'X-XSS-Protection: 0' "
                    "and rely on CSP instead."
                ),
                evidence=f"X-XSS-Protection: {xxp}",
                url=url,
            )
        )

    for h in _INFO_LEAK_HEADERS:
        if h in lower_headers:
            findings.append(
                Finding(
                    id=f"HDR-INFO-{h.upper()}",
                    title=f"Server/technology disclosure via '{h}' header",
                    severity=Severity.INFO,
                    owasp_category="A05:2021 - Security Misconfiguration",
                    description=f"'{h}' header reveals implementation details: {lower_headers[h]!r}.",
                    evidence=f"{h}: {lower_headers[h]}",
                    recommendation="Suppress or generalize this header at the reverse proxy/web server level.",
                    url=url,
                )
            )

    return findings
