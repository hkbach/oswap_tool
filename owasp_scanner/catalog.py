"""Static metadata for every finding type, and the enrichment applied to each finding.

Checks decide *what* they observed (id, severity, evidence) and *where*
(``instance_key``). This module adds the fields that depend only on the finding
type — CWE, confidence, references — and the cross-scan ``fingerprint``, so
that knowledge lives in one declarative table (FR-MODEL-01, NFR-MAINT-02).
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, replace
from urllib.parse import urlsplit

from .models import Finding

_CWE_URL = "https://cwe.mitre.org/data/definitions/{}.html"

_TOP10_A01 = "https://owasp.org/Top10/A01_2021-Broken_Access_Control/"
_TOP10_A02 = "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/"
_TOP10_A05 = "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/"
_SECURE_HEADERS = "https://owasp.org/www-project-secure-headers/"
_CS = "https://cheatsheetseries.owasp.org/cheatsheets/"
_CS_HEADERS = _CS + "HTTP_Headers_Cheat_Sheet.html"
_CS_HSTS = _CS + "HTTP_Strict_Transport_Security_Cheat_Sheet.html"
_CS_CSP = _CS + "Content_Security_Policy_Cheat_Sheet.html"
_CS_CLICKJACKING = _CS + "Clickjacking_Defense_Cheat_Sheet.html"
_CS_SESSION = _CS + "Session_Management_Cheat_Sheet.html"
_CS_TLS = _CS + "Transport_Layer_Security_Cheat_Sheet.html"
_CS_HTML5 = _CS + "HTML5_Security_Cheat_Sheet.html"

# Informational findings that do not describe a weakness, so they carry no CWE.
NOT_A_WEAKNESS = frozenset({"TLS-CONN-FAILED", "TLS-CERT-PARSE-FAILED", "EXPOSURE-SECURITY-TXT"})


@dataclass(frozen=True)
class FindingMeta:
    cwe: str
    confidence: str  # "high" | "medium" | "low"
    references: tuple[str, ...]


def _meta(cwe: str, confidence: str, *refs: str) -> FindingMeta:
    links = refs + ((_CWE_URL.format(cwe.split("-")[1]),) if cwe else ())
    return FindingMeta(cwe, confidence, links)


# Confidence reflects how directly the finding was observed:
#   high   - read straight from the response or handshake (headers, cookies, TLS, CORS)
#   medium - inferred from an HTTP 200 without checking the content (sensitive paths)
#   low    - a hint only (robots.txt / sitemap.xml mention a sensitive-sounding path)
_HDR = (_SECURE_HEADERS, _CS_HEADERS, _TOP10_A05)
_EXPOSED = (_TOP10_A01,)

FINDING_CATALOG: dict[str, FindingMeta] = {
    # security headers
    "HDR-STRICT-TRANSPORT-SECURITY-MISSING": _meta("CWE-319", "high", _CS_HSTS, _SECURE_HEADERS, _TOP10_A02),
    "HDR-CONTENT-SECURITY-POLICY-MISSING": _meta("CWE-693", "high", _CS_CSP, *_HDR),
    "HDR-X-CONTENT-TYPE-OPTIONS-MISSING": _meta("CWE-693", "high", *_HDR),
    "HDR-X-FRAME-OPTIONS-MISSING": _meta("CWE-1021", "high", _CS_CLICKJACKING, *_HDR),
    "HDR-XFO-WEAK": _meta("CWE-1021", "high", _CS_CLICKJACKING, *_HDR),
    "HDR-REFERRER-POLICY-MISSING": _meta("CWE-200", "high", *_HDR),
    "HDR-PERMISSIONS-POLICY-MISSING": _meta("CWE-693", "high", *_HDR),
    "HDR-CSP-UNSAFE": _meta("CWE-693", "high", _CS_CSP, _SECURE_HEADERS),
    "HDR-XXP-LEGACY": _meta("CWE-693", "high", *_HDR),
    "HDR-INFO-SERVER": _meta("CWE-497", "high", *_HDR),
    "HDR-INFO-X-POWERED-BY": _meta("CWE-497", "high", *_HDR),
    "HDR-INFO-X-ASPNET-VERSION": _meta("CWE-497", "high", *_HDR),
    "HDR-INFO-X-ASPNETMVC-VERSION": _meta("CWE-497", "high", *_HDR),
    # cookies: the check refines the CWE to the most important missing attribute
    "COOKIE-FLAGS-MISSING": _meta("CWE-614", "high", _CS_SESSION, _TOP10_A05),
    # TLS
    "TLS-CONN-FAILED": _meta("", "high", _CS_TLS),
    "TLS-WEAK-PROTOCOL": _meta("CWE-327", "high", _CS_TLS, _TOP10_A02),
    "TLS-WEAK-CIPHER": _meta("CWE-327", "high", _CS_TLS, _TOP10_A02),
    "TLS-CERT-NOT-YET-VALID": _meta("CWE-298", "high", _CS_TLS, _TOP10_A02),
    "TLS-CERT-EXPIRED": _meta("CWE-298", "high", _CS_TLS, _TOP10_A02),
    "TLS-CERT-EXPIRING-SOON": _meta("CWE-298", "high", _CS_TLS, _TOP10_A02),
    "TLS-CERT-NOT-TRUSTED": _meta("CWE-295", "high", _CS_TLS, _TOP10_A02),
    "TLS-CERT-PARSE-FAILED": _meta("", "high", _CS_TLS),
    "TLS-NO-HTTPS-REDIRECT": _meta("CWE-319", "high", _CS_HSTS, _CS_TLS, _TOP10_A02),
    # CORS
    "CORS-WILDCARD-WITH-CREDENTIALS": _meta("CWE-942", "high", _CS_HTML5, _TOP10_A05),
    "CORS-REFLECTS-ARBITRARY-ORIGIN": _meta("CWE-942", "high", _CS_HTML5, _TOP10_A05),
    "CORS-WILDCARD": _meta("CWE-942", "high", _CS_HTML5, _TOP10_A05),
    # exposed files: status 200 only, content not verified yet (FR-DET-01)
    "EXPOSURE-GIT-HEAD": _meta("CWE-527", "medium", *_EXPOSED),
    "EXPOSURE-GIT-CONFIG": _meta("CWE-527", "medium", *_EXPOSED),
    "EXPOSURE-SVN-ENTRIES": _meta("CWE-527", "medium", *_EXPOSED),
    "EXPOSURE-ENV": _meta("CWE-538", "medium", *_EXPOSED),
    "EXPOSURE-ENV-LOCAL": _meta("CWE-538", "medium", *_EXPOSED),
    "EXPOSURE-ENV-PRODUCTION": _meta("CWE-538", "medium", *_EXPOSED),
    "EXPOSURE-WEB-CONFIG": _meta("CWE-538", "medium", *_EXPOSED),
    "EXPOSURE-DOCKER-COMPOSE": _meta("CWE-538", "medium", *_EXPOSED),
    "EXPOSURE-ID-RSA": _meta("CWE-538", "medium", *_EXPOSED),
    "EXPOSURE-DS-STORE": _meta("CWE-538", "medium", *_EXPOSED),
    "EXPOSURE-WP-CONFIG-BAK": _meta("CWE-530", "medium", *_EXPOSED),
    "EXPOSURE-CONFIG-PHP-BAK": _meta("CWE-530", "medium", *_EXPOSED),
    "EXPOSURE-BACKUP-ZIP": _meta("CWE-530", "medium", *_EXPOSED),
    "EXPOSURE-BACKUP-SQL": _meta("CWE-530", "medium", *_EXPOSED),
    "EXPOSURE-PHPINFO": _meta("CWE-497", "medium", *_EXPOSED),
    "EXPOSURE-SERVER-STATUS": _meta("CWE-497", "medium", *_EXPOSED),
    "EXPOSURE-SECURITY-TXT": _meta("", "medium", "https://securitytxt.org/"),
    # other exposure checks
    "EXPOSURE-DIR-LISTING": _meta("CWE-548", "high", _TOP10_A05),
    "EXPOSURE-ROBOTS-HINTS": _meta("CWE-200", "low", _TOP10_A01),
    "EXPOSURE-SITEMAP-HINTS": _meta("CWE-200", "low", _TOP10_A01),
}


def _origin(target: str) -> str:
    parts = urlsplit(target)
    scheme = (parts.scheme or "https").lower()
    port = parts.port or {"http": 80, "https": 443}.get(scheme)
    return f"{scheme}://{(parts.hostname or '').lower()}:{port}"


def fingerprint(finding_id: str, instance_key: str, target: str) -> str:
    """Stable key for one finding at one place on one site, across scans.

    Uses the target's origin (scheme, host, port), not its path, so scanning the
    same site from a different start page yields the same fingerprints.
    """
    material = f"{finding_id}|{instance_key}|{_origin(target)}"
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:32]


def enrich(finding: Finding, target: str) -> Finding:
    """Return ``finding`` with catalog metadata and fingerprint filled in."""
    meta = FINDING_CATALOG.get(finding.id)
    return replace(
        finding,
        cwe=finding.cwe or (meta.cwe if meta else ""),
        confidence=finding.confidence or (meta.confidence if meta else "low"),
        references=list(finding.references or (meta.references if meta else ())),
        fingerprint=fingerprint(finding.id, finding.instance_key, target),
    )
