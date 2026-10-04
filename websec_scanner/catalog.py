"""Static metadata for every finding type, and the enrichment applied to each finding.

Checks decide *what* they observed (id, severity, evidence) and *where*
(``instance_key``). This module adds the fields that depend only on the finding
type — CWE, confidence, references — and the cross-scan ``fingerprint``, so
that knowledge lives in one declarative table (FR-MODEL-01, NFR-MAINT-02).
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable
from dataclasses import dataclass, replace
from urllib.parse import urlsplit

from . import cvss
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
    # CVSS v3.1 vector for this *type* of finding (FR-MODEL-03): a generic, estimated
    # severity for the underlying weakness class, not an assessment of one target.
    # Three rules, from the vector review of 2026-10-01:
    #   1. the vector here is the *worst case* for this type of finding;
    #   2. a check overrides it per finding when the evidence shows a milder case
    #      (enrich() then recomputes the score from the overriding vector);
    #   3. findings that are not a scorable weakness (early warnings, hints, anything
    #      whose default severity is INFO) carry no CVSS at all - see NO_CVSS.
    # Filled in below from _CVSS_VECTORS, not per entry, so the vector choices stay in
    # one reviewable table rather than scattered across the catalog.
    cvss_vector: str = ""
    cvss_score: float | None = None


def _meta(cwe: str, confidence: str, *refs: str) -> FindingMeta:
    links = refs + ((_CWE_URL.format(cwe.split("-")[1]),) if cwe else ())
    return FindingMeta(cwe, confidence, links)


# Confidence reflects how directly the finding was observed:
#   high   - read straight from the response or handshake (headers, cookies, TLS, CORS)
#   high   - also: exposed files whose content matched the file type (FR-DET-01)
#   medium - an indirect observation (none today)
#   low    - a hint only (robots.txt / sitemap.xml mention a sensitive-sounding path);
#            TLS findings are lowered to low when the handshake looks intercepted (FR-DET-16)
_HDR = (_SECURE_HEADERS, _CS_HEADERS, _TOP10_A05)
_EXPOSED = (_TOP10_A01,)

FINDING_CATALOG: dict[str, FindingMeta] = {
    # security headers
    "HDR-STRICT-TRANSPORT-SECURITY-MISSING": _meta("CWE-319", "high", _CS_HSTS, _SECURE_HEADERS, _TOP10_A02),
    "HDR-HSTS-MISSING-ON-START-HOST": _meta("CWE-319", "high", _CS_HSTS, _TOP10_A02),
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
    "TLS-CERT-EXPIRED": _meta("CWE-324", "high", _CS_TLS, _TOP10_A02),
    "TLS-CERT-EXPIRING-SOON": _meta("CWE-324", "high", _CS_TLS, _TOP10_A02),
    "TLS-CERT-NOT-TRUSTED": _meta("CWE-295", "high", _CS_TLS, _TOP10_A02),
    "TLS-CERT-PARSE-FAILED": _meta("", "high", _CS_TLS),
    "TLS-NO-HTTPS-REDIRECT": _meta("CWE-319", "high", _CS_HSTS, _CS_TLS, _TOP10_A02),
    # CORS
    "CORS-WILDCARD-WITH-CREDENTIALS": _meta("CWE-942", "high", _CS_HTML5, _TOP10_A05),
    "CORS-REFLECTS-ARBITRARY-ORIGIN": _meta("CWE-942", "high", _CS_HTML5, _TOP10_A05),
    "CORS-WILDCARD": _meta("CWE-942", "high", _CS_HTML5, _TOP10_A05),
    # exposed files: HTTP 200 and content matching the file type (FR-DET-01)
    "EXPOSURE-GIT-HEAD": _meta("CWE-527", "high", *_EXPOSED),
    "EXPOSURE-GIT-CONFIG": _meta("CWE-527", "high", *_EXPOSED),
    "EXPOSURE-SVN-ENTRIES": _meta("CWE-527", "high", *_EXPOSED),
    "EXPOSURE-ENV": _meta("CWE-538", "high", *_EXPOSED),
    "EXPOSURE-ENV-LOCAL": _meta("CWE-538", "high", *_EXPOSED),
    "EXPOSURE-ENV-PRODUCTION": _meta("CWE-538", "high", *_EXPOSED),
    "EXPOSURE-WEB-CONFIG": _meta("CWE-538", "high", *_EXPOSED),
    "EXPOSURE-DOCKER-COMPOSE": _meta("CWE-538", "high", *_EXPOSED),
    "EXPOSURE-ID-RSA": _meta("CWE-538", "high", *_EXPOSED),
    "EXPOSURE-DS-STORE": _meta("CWE-538", "high", *_EXPOSED),
    "EXPOSURE-WP-CONFIG-BAK": _meta("CWE-530", "high", *_EXPOSED),
    "EXPOSURE-CONFIG-PHP-BAK": _meta("CWE-530", "high", *_EXPOSED),
    "EXPOSURE-BACKUP-ZIP": _meta("CWE-530", "high", *_EXPOSED),
    "EXPOSURE-BACKUP-SQL": _meta("CWE-530", "high", *_EXPOSED),
    "EXPOSURE-PHPINFO": _meta("CWE-497", "high", *_EXPOSED),
    "EXPOSURE-SERVER-STATUS": _meta("CWE-497", "high", *_EXPOSED),
    "EXPOSURE-SECURITY-TXT": _meta("", "high", "https://securitytxt.org/"),
    # other exposure checks
    "EXPOSURE-DIR-LISTING": _meta("CWE-548", "high", _TOP10_A05),
    "EXPOSURE-ROBOTS-HINTS": _meta("CWE-200", "low", _TOP10_A01),
    "EXPOSURE-SITEMAP-HINTS": _meta("CWE-200", "low", _TOP10_A01),
}

# Findings that are a real observation but not a scorable weakness, so they carry no CVSS:
# the three in NOT_A_WEAKNESS, plus early warnings, hints, and (decision C1 of the 2026-10-01
# vector review) everything whose default severity is INFO - a score printed next to "INFO"
# reads as a contradiction.
NO_CVSS: frozenset[str] = NOT_A_WEAKNESS | frozenset(
    {
        "TLS-CERT-EXPIRING-SOON",  # the certificate is still valid; this is an advance warning
        "EXPOSURE-ROBOTS-HINTS",  # a hint only, and robots.txt is public by design
        "EXPOSURE-SITEMAP-HINTS",
        "HDR-XXP-LEGACY",  # discloses nothing; modern browsers ignore the header
        "HDR-PERMISSIONS-POLICY-MISSING",
        "HDR-INFO-SERVER",
        "HDR-INFO-X-POWERED-BY",
        "HDR-INFO-X-ASPNET-VERSION",
        "HDR-INFO-X-ASPNETMVC-VERSION",
        "CORS-WILDCARD",  # '*' without credentials exposes only what is already public
    }
)

# CVSS v3.1 base vectors by finding type (FR-MODEL-03), revised by the vector review of
# 2026-10-01. `[CONFIRM]` Each is a generic, estimated vector for the *worst case* of that
# type of weakness, not an assessment of one target; checks override it per finding for
# milder cases (see the CVSS_* constants below). It is deliberately a separate scale from
# this tool's own Severity (which also folds in D3-style exploitability-in-context), so the
# two do not always line up, and the table still needs a security-team pass before the
# scores are presented as authoritative to a paying customer.
# Grouped by the scenario each one describes, so the reasoning lives in one place:
_UNAUTH_SECRET_FILE_READ = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"  # noqa: S105 - not a credential, a CVSS vector; 7.5
_UNAUTH_LIMITED_INFO_READ = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"  # 5.3: non-secret info/structure disclosure
_TLS_PASSIVE_EAVESDROP = "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N"  # 5.9: traffic can be decrypted, not altered
_TLS_ACTIVE_MITM = "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N"  # 7.4: no encryption left to break (NULL/EXPORT)
# 6.8: an on-path attacker, but the victim has to navigate over http:// first.
_TLS_STRIP_NEEDS_HTTP_NAV = "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N"
# 6.8 (same vector, different story): an on-path attacker, and the victim has to click past
# the browser's certificate warning - which HSTS turns into a hard block.
_TLS_CERT_WARNING_CLICKTHROUGH = "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N"
# AC:H here is this tool's convention for "needs a second bug (e.g. XSS) to matter", which is
# not how the CVSS spec defines Attack Complexity; the spec scores the conditions for
# exploiting *this* weakness alone.
_HEADER_HARDENING_GAP = "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N"  # 4.2
_HEADER_MINOR_HARDENING_GAP = "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N"  # 3.1: narrower version of the above
_CLICKJACKING = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N"  # 4.3: victim lured into clicking framed UI
_CLICKJACKING_WEAK = "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:L/A:N"  # 3.1: partial protection present
_SESSION_COOKIE_EXPOSED = "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N"  # 5.3: no Secure, so the cookie can leak
_CORS_WILDCARD_NOT_BROWSER_EXPLOITABLE = "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N"  # 3.7: browsers refuse it (D3)
_CORS_CROSS_ORIGIN_READ_VIA_VICTIM = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N"  # 6.5: needs a lured victim

# Public: the milder cases a check overrides the catalog with, per finding (never a raw
# vector string inside a check). enrich() recomputes the score from whichever vector wins.
CVSS_CORS_REFLECT_WITHOUT_CREDENTIALS = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N"  # 4.3: no authenticated data
CVSS_COOKIE_READABLE_BY_SCRIPT = "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N"  # 3.1: Secure set, HttpOnly missing
CVSS_COOKIE_SENT_CROSS_SITE = "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:L/A:N"  # 3.1: only SameSite missing
CVSS_TLS_CIPHER_BROKEN_BUT_ENCRYPTING = _TLS_PASSIVE_EAVESDROP  # 5.9: RC4/3DES/MD5 still encrypt

_CVSS_VECTORS: dict[str, str] = {
    # security headers: missing/weak hardening, each needs another condition to be exploitable
    "HDR-STRICT-TRANSPORT-SECURITY-MISSING": _TLS_STRIP_NEEDS_HTTP_NAV,
    "HDR-HSTS-MISSING-ON-START-HOST": _HEADER_MINOR_HARDENING_GAP,
    "HDR-CONTENT-SECURITY-POLICY-MISSING": _HEADER_HARDENING_GAP,
    "HDR-CSP-UNSAFE": _HEADER_HARDENING_GAP,
    "HDR-X-CONTENT-TYPE-OPTIONS-MISSING": _HEADER_MINOR_HARDENING_GAP,
    "HDR-X-FRAME-OPTIONS-MISSING": _CLICKJACKING,
    "HDR-XFO-WEAK": _CLICKJACKING_WEAK,
    "HDR-REFERRER-POLICY-MISSING": _HEADER_MINOR_HARDENING_GAP,
    # cookies: the worst case is a cookie without Secure; check_cookies() lowers it per cookie
    "COOKIE-FLAGS-MISSING": _SESSION_COOKIE_EXPOSED,
    # TLS
    "TLS-WEAK-PROTOCOL": _TLS_PASSIVE_EAVESDROP,
    "TLS-WEAK-CIPHER": _TLS_ACTIVE_MITM,  # worst case NULL/EXPORT; the check lowers RC4/3DES/MD5
    "TLS-CERT-NOT-YET-VALID": _TLS_CERT_WARNING_CLICKTHROUGH,
    "TLS-CERT-EXPIRED": _TLS_CERT_WARNING_CLICKTHROUGH,
    "TLS-CERT-NOT-TRUSTED": _TLS_CERT_WARNING_CLICKTHROUGH,
    "TLS-NO-HTTPS-REDIRECT": _TLS_STRIP_NEEDS_HTTP_NAV,
    # CORS: the worst case D3 assigns to the id; check_cors() overrides the milder case
    "CORS-WILDCARD-WITH-CREDENTIALS": _CORS_WILDCARD_NOT_BROWSER_EXPLOITABLE,
    "CORS-REFLECTS-ARBITRARY-ORIGIN": _CORS_CROSS_ORIGIN_READ_VIA_VICTIM,
    # exposed files: full secrets/credentials vs. limited system/version info
    "EXPOSURE-GIT-HEAD": _UNAUTH_SECRET_FILE_READ,
    "EXPOSURE-GIT-CONFIG": _UNAUTH_SECRET_FILE_READ,
    "EXPOSURE-SVN-ENTRIES": _UNAUTH_SECRET_FILE_READ,
    "EXPOSURE-ENV": _UNAUTH_SECRET_FILE_READ,
    "EXPOSURE-ENV-LOCAL": _UNAUTH_SECRET_FILE_READ,
    "EXPOSURE-ENV-PRODUCTION": _UNAUTH_SECRET_FILE_READ,
    "EXPOSURE-WEB-CONFIG": _UNAUTH_SECRET_FILE_READ,
    "EXPOSURE-DOCKER-COMPOSE": _UNAUTH_SECRET_FILE_READ,
    "EXPOSURE-ID-RSA": _UNAUTH_SECRET_FILE_READ,
    "EXPOSURE-WP-CONFIG-BAK": _UNAUTH_SECRET_FILE_READ,
    "EXPOSURE-CONFIG-PHP-BAK": _UNAUTH_SECRET_FILE_READ,
    "EXPOSURE-BACKUP-ZIP": _UNAUTH_SECRET_FILE_READ,
    "EXPOSURE-BACKUP-SQL": _UNAUTH_SECRET_FILE_READ,
    "EXPOSURE-DS-STORE": _UNAUTH_LIMITED_INFO_READ,
    "EXPOSURE-PHPINFO": _UNAUTH_LIMITED_INFO_READ,
    "EXPOSURE-SERVER-STATUS": _UNAUTH_LIMITED_INFO_READ,
    # other exposure checks
    "EXPOSURE-DIR-LISTING": _UNAUTH_LIMITED_INFO_READ,
}
for _id, _vector in _CVSS_VECTORS.items():
    FINDING_CATALOG[_id] = replace(FINDING_CATALOG[_id], cvss_vector=_vector, cvss_score=cvss.base_score(_vector))
del _id, _vector


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
    vector = finding.cvss_vector or (meta.cvss_vector if meta else "")
    return replace(
        finding,
        cwe=finding.cwe or (meta.cwe if meta else ""),
        confidence=finding.confidence or (meta.confidence if meta else "low"),
        references=list(finding.references or (meta.references if meta else ())),
        cvss_vector=vector,
        # Always derived from the winning vector: a check that overrode the vector for this
        # one finding must not end up carrying the catalog's score for the worst case.
        cvss_score=cvss.base_score(vector) if vector else None,
        fingerprint=fingerprint(finding.id, finding.instance_key, target),
    )


@dataclass(frozen=True)
class CheckGroup:
    """One test target: a group of checks that the user can select for a scan (SRS 4.11)."""

    id: str
    title: str
    description: str
    checks: tuple[str, ...]  # check names as they appear in ScanResult.checks_run


# The order is the order of the report sections, the web UI and ``--list-checks``.
CHECK_GROUPS: tuple[CheckGroup, ...] = (
    CheckGroup(
        "headers",
        "Security headers",
        "HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy "
        "and headers that disclose server software.",
        ("security-headers", "hsts-start-host"),
    ),
    CheckGroup("cookies", "Cookies", "Secure, HttpOnly and SameSite attributes of the cookies set.", ("cookies",)),
    CheckGroup(
        "tls",
        "TLS/SSL",
        "Protocol versions and weak cipher suites the server accepts (standard handshakes, never "
        "completed), negotiated protocol and cipher, certificate validity period and trust "
        "(up to 13 TLS connections).",
        ("tls",),
    ),
    CheckGroup(
        "https-redirect",
        "HTTP to HTTPS redirect",
        "Whether plain HTTP is redirected to HTTPS.",
        ("http-to-https-redirect",),
    ),
    CheckGroup(
        "cors", "CORS", "Access-Control-Allow-Origin for a test Origin, with and without credentials.", ("cors",)
    ),
    CheckGroup(
        "exposed-files",
        "Exposed files",
        "Well-known sensitive files (.git, .env, backups, keys, ...), reported only when the content matches.",
        ("sensitive-paths",),
    ),
    CheckGroup(
        "directory-listing",
        "Directory listing",
        "Common directories that return a browsable file index.",
        ("directory-listing",),
    ),
    CheckGroup(
        "robots-sitemap",
        "robots.txt / sitemap.xml",
        "Sensitive-sounding paths advertised in robots.txt and sitemap.xml (hints, low confidence).",
        ("robots-sitemap",),
    ),
)
GROUP_IDS: tuple[str, ...] = tuple(g.id for g in CHECK_GROUPS)
_GROUP_OF_CHECK = {check: g.id for g in CHECK_GROUPS for check in g.checks}


def group_of_check(check: str) -> str:
    """The group id that a check name (``checks_run`` entry, ``finding.check``) belongs to."""
    return _GROUP_OF_CHECK[check]


def normalize_groups(groups: Iterable[str]) -> list[str]:
    """Validate a group selection; returns the ids in table order. Raises ValueError."""
    wanted = {str(g).strip().lower() for g in groups}
    unknown = sorted(wanted - set(GROUP_IDS))
    if unknown:
        raise ValueError(f"Unknown check group(s): {', '.join(unknown)}. Valid groups: {', '.join(GROUP_IDS)}")
    if not wanted:
        raise ValueError("Select at least one check group")
    return [g for g in GROUP_IDS if g in wanted]
