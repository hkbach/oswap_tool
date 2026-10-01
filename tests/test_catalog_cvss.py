"""FR-MODEL-03 / FIX-10: the CVSS vector table in catalog.py, pinned finding by finding.

Source: the CVSS vector review of 2026-10-01 (CVSS-FIXES), decisions C1 (findings whose
default severity is INFO carry no CVSS) and C2 (CWE-324 for expired/expiring certificates,
CWE-298 kept for not-yet-valid). The expected scores below are that review's table.
"""

from __future__ import annotations

import pytest
from test_checks import _cors_handler

from websec_scanner import catalog, cvss
from websec_scanner.checks import cookies, cors_check, headers, tls_check
from websec_scanner.http_utils import build_session
from websec_scanner.models import Finding, Severity

P = "CVSS:3.1/"

# id -> (vector without the "CVSS:3.1/" prefix, base score), or None for "no CVSS".
EXPECTED: dict[str, tuple[str, float] | None] = {
    # security headers
    "HDR-STRICT-TRANSPORT-SECURITY-MISSING": ("AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N", 6.8),
    "HDR-HSTS-MISSING-ON-START-HOST": ("AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N", 3.1),
    "HDR-CONTENT-SECURITY-POLICY-MISSING": ("AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N", 4.2),
    "HDR-CSP-UNSAFE": ("AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N", 4.2),
    "HDR-X-CONTENT-TYPE-OPTIONS-MISSING": ("AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N", 3.1),
    "HDR-X-FRAME-OPTIONS-MISSING": ("AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N", 4.3),
    "HDR-XFO-WEAK": ("AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:L/A:N", 3.1),
    "HDR-REFERRER-POLICY-MISSING": ("AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N", 3.1),
    "HDR-PERMISSIONS-POLICY-MISSING": None,
    "HDR-XXP-LEGACY": None,
    "HDR-INFO-SERVER": None,
    "HDR-INFO-X-POWERED-BY": None,
    "HDR-INFO-X-ASPNET-VERSION": None,
    "HDR-INFO-X-ASPNETMVC-VERSION": None,
    # cookies: the catalog holds the worst case (no Secure); checks lower it per cookie
    "COOKIE-FLAGS-MISSING": ("AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N", 5.3),
    # TLS
    "TLS-WEAK-PROTOCOL": ("AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N", 5.9),
    "TLS-WEAK-CIPHER": ("AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N", 7.4),
    "TLS-CERT-NOT-YET-VALID": ("AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N", 6.8),
    "TLS-CERT-EXPIRED": ("AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N", 6.8),
    "TLS-CERT-NOT-TRUSTED": ("AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N", 6.8),
    "TLS-CERT-EXPIRING-SOON": None,
    "TLS-NO-HTTPS-REDIRECT": ("AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N", 6.8),
    "TLS-CONN-FAILED": None,
    "TLS-CERT-PARSE-FAILED": None,
    # CORS
    "CORS-WILDCARD-WITH-CREDENTIALS": ("AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N", 3.7),
    "CORS-REFLECTS-ARBITRARY-ORIGIN": ("AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N", 6.5),
    "CORS-WILDCARD": None,
    # exposed files: full secrets/credentials
    **{
        f"EXPOSURE-{name}": ("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5)
        for name in (
            "GIT-HEAD",
            "GIT-CONFIG",
            "SVN-ENTRIES",
            "ENV",
            "ENV-LOCAL",
            "ENV-PRODUCTION",
            "WEB-CONFIG",
            "DOCKER-COMPOSE",
            "ID-RSA",
            "WP-CONFIG-BAK",
            "CONFIG-PHP-BAK",
            "BACKUP-ZIP",
            "BACKUP-SQL",
        )
    },  # fmt: skip
    # exposed files and directories: limited system/structure information
    **{
        f"EXPOSURE-{name}": ("AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", 5.3)
        for name in ("DS-STORE", "PHPINFO", "SERVER-STATUS", "DIR-LISTING")
    },
    # hints and good-practice observations: not a scorable weakness
    "EXPOSURE-ROBOTS-HINTS": None,
    "EXPOSURE-SITEMAP-HINTS": None,
    "EXPOSURE-SECURITY-TXT": None,
}


def _info_severity_ids() -> set[str]:
    """Finding ids whose default severity is INFO, for decision C1."""
    ids = {f"HDR-{h.upper()}-MISSING" for h, (sev, _, _) in headers._REQUIRED_HEADERS.items() if sev is Severity.INFO}
    ids |= {f"HDR-INFO-{h.upper()}" for h in headers._INFO_LEAK_HEADERS}  # all INFO
    # Set inside a check body, so there is nothing to read them from; keep in sync by hand.
    ids |= {"HDR-XXP-LEGACY", "CORS-WILDCARD", "TLS-CONN-FAILED", "TLS-CERT-PARSE-FAILED", "EXPOSURE-SECURITY-TXT"}
    return ids


def test_the_expected_table_covers_every_finding_type():
    assert set(EXPECTED) == set(catalog.FINDING_CATALOG)


def test_every_scorable_finding_has_a_vector_and_every_vector_has_a_finding():
    assert set(catalog.FINDING_CATALOG) - catalog.NO_CVSS == set(catalog._CVSS_VECTORS)


@pytest.mark.parametrize("finding_id", sorted(EXPECTED))
def test_vector_and_score_match_the_review(finding_id):
    meta = catalog.FINDING_CATALOG[finding_id]
    expected = EXPECTED[finding_id]
    if expected is None:
        assert finding_id in catalog.NO_CVSS
        assert meta.cvss_vector == "" and meta.cvss_score is None
    else:
        vector, score = expected
        assert meta.cvss_vector == P + vector
        assert meta.cvss_score == score == cvss.base_score(meta.cvss_vector)


def test_findings_that_are_only_informational_carry_no_score():
    # C1: an INFO finding showing a CVSS score next to it would contradict its own severity.
    assert _info_severity_ids() <= catalog.NO_CVSS


def test_cors_wildcard_is_never_scored_above_the_same_wildcard_with_credentials():
    # FIX-01: '*' alone exposes only data that is already public, so it cannot be the worse of the two.
    wildcard = catalog.FINDING_CATALOG["CORS-WILDCARD"].cvss_score
    with_credentials = catalog.FINDING_CATALOG["CORS-WILDCARD-WITH-CREDENTIALS"].cvss_score
    assert wildcard is None or wildcard <= with_credentials


def test_missing_hsts_and_missing_redirect_describe_the_same_attack():
    # FIX-02: both let an on-path attacker strip TLS after the victim starts on http://.
    assert (
        catalog.FINDING_CATALOG["TLS-NO-HTTPS-REDIRECT"].cvss_score
        == catalog.FINDING_CATALOG["HDR-STRICT-TRANSPORT-SECURITY-MISSING"].cvss_score
    )


def test_certificate_cwe_follows_the_review_decision():
    # C2: the server using a key past its expiry is CWE-324; CWE-298 (client not checking
    # expiry) is kept for not-yet-valid until a security reviewer revisits it.
    assert catalog.FINDING_CATALOG["TLS-CERT-EXPIRED"].cwe == "CWE-324"
    assert catalog.FINDING_CATALOG["TLS-CERT-EXPIRING-SOON"].cwe == "CWE-324"
    assert catalog.FINDING_CATALOG["TLS-CERT-NOT-YET-VALID"].cwe == "CWE-298"


@pytest.mark.parametrize("finding_id", sorted(catalog._CVSS_VECTORS))
def test_every_vector_is_a_complete_cvss_31_base_vector(finding_id):
    metrics = cvss.parse_vector(catalog._CVSS_VECTORS[finding_id])
    assert set(metrics) == {"AV", "AC", "PR", "UI", "S", "C", "I", "A"}


@pytest.mark.parametrize(
    "raw, expected_score",
    [
        ("s=1; HttpOnly; SameSite=Lax", 5.3),  # no Secure: the catalog's worst case
        ("s=1; Secure; SameSite=Lax", 3.1),  # Secure set, readable by script
        ("s=1; Secure; HttpOnly", 3.1),  # only SameSite missing
    ],
)
def test_cookie_score_follows_the_attribute_that_is_missing(raw, expected_score):
    (finding,) = cookies.check_cookies("https://t/", [raw])
    enriched = catalog.enrich(finding, "https://t/")
    assert enriched.cvss_score == expected_score
    assert enriched.cvss_score == cvss.base_score(enriched.cvss_vector)


@pytest.mark.parametrize("credentials, expected_score", [("true", 6.5), (None, 4.3)])
def test_reflected_cors_origin_scores_lower_without_credentials(credentials, expected_score, http_server):
    (finding,) = cors_check.check_cors(build_session(timeout=2), http_server(_cors_handler("echo", credentials)))
    assert finding.id == "CORS-REFLECTS-ARBITRARY-ORIGIN"
    enriched = catalog.enrich(finding, "https://t/")
    assert enriched.cvss_score == expected_score == cvss.base_score(enriched.cvss_vector)


@pytest.mark.parametrize(
    "cipher_name, expected_score",
    [("EXP-RC4-MD5", 7.4), ("ECDHE-RSA-NULL-SHA", 7.4), ("ECDHE-RSA-RC4-SHA", 5.9), ("DES-CBC3-SHA", 5.9)],
)
def test_weak_cipher_scores_lower_when_the_traffic_is_still_encrypted(cipher_name, expected_score):
    # NULL/EXPORT leave nothing to break, so they keep the catalog's worst case.
    finding = Finding(
        id="TLS-WEAK-CIPHER",
        title="t",
        severity=Severity.HIGH,
        owasp_category="A02:2021 - Cryptographic Failures",
        description="d",
        instance_key="t:443",
        cvss_vector=tls_check.cipher_cvss_vector(cipher_name),
    )
    assert catalog.enrich(finding, "https://t/").cvss_score == expected_score


def test_a_check_can_lower_the_score_for_one_instance():
    # FIX-07: the catalog is the worst case; a check that observed a milder case overrides it,
    # and the score is recomputed from the overriding vector, not kept from the catalog.
    milder = P + "AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N"
    finding = Finding(
        id="COOKIE-FLAGS-MISSING",
        title="t",
        severity=Severity.LOW,
        owasp_category="A05:2021 - Security Misconfiguration",
        description="d",
        instance_key="session",
        cvss_vector=milder,
    )
    enriched = catalog.enrich(finding, "https://example.com/")
    assert enriched.cvss_vector == milder
    assert enriched.cvss_score == cvss.base_score(milder) == 3.1
