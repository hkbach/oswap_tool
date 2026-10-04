"""FR-DET-17: which cipher suites count as weak, and how badly.

Cipher names are the OpenSSL spellings that ``ssl.SSLSocket.cipher()`` returns, so the
table is checked against real suite names rather than IANA ones.
"""

from __future__ import annotations

import pytest

from websec_scanner import catalog, cvss
from websec_scanner.checks import tls_check

# OpenSSL name -> why it is weak. None means "do not flag this suite".
WEAK = {
    # no encryption at all
    "NULL-SHA256": "no-encryption",
    "ECDHE-RSA-NULL-SHA": "no-encryption",
    # export grade: 40/56-bit keys by design
    "EXP-RC4-MD5": "no-encryption",
    "EXP-DES-CBC-SHA": "no-encryption",
    "EXP1024-DES-CBC-SHA": "no-encryption",
    "TLS_RSA_EXPORT_WITH_RC4_40_MD5": "no-encryption",
    # encrypted but nobody is authenticated, so an on-path attacker just takes over
    "ADH-AES256-SHA": "unauthenticated",
    "AECDH-AES128-SHA": "unauthenticated",
    # broken or too small, but the traffic is still encrypted
    "ECDHE-RSA-RC4-SHA": "broken",
    "RC4-MD5": "broken",
    "DES-CBC-SHA": "broken",  # single DES, 56-bit: the gap FR-DET-17 closes
    "DES-CBC3-SHA": "broken",  # 3DES, 64-bit block (SWEET32)
    "ECDHE-RSA-DES-CBC3-SHA": "broken",
    "EXP-RC2-CBC-MD5": "no-encryption",  # export beats the RC2 reason
    "IDEA-CBC-SHA": "broken",
    "ECDHE-RSA-AES128-SHA256": None,
    "ECDHE-RSA-AES256-GCM-SHA384": None,
    "ECDHE-RSA-CHACHA20-POLY1305": None,
    "TLS_AES_128_GCM_SHA256": None,
    "TLS_CHACHA20_POLY1305_SHA256": None,
}


@pytest.mark.parametrize("cipher_name, reason", sorted(WEAK.items(), key=lambda kv: kv[0]))
def test_weak_cipher_classification(cipher_name, reason):
    assert tls_check.weak_cipher_reason(cipher_name) == reason


def test_a_modern_suite_is_never_flagged():
    assert not [name for name, reason in WEAK.items() if reason is None and tls_check.weak_cipher_reason(name)]


@pytest.mark.parametrize(
    "cipher_name, expected_score",
    [
        ("EXP1024-DES-CBC-SHA", 7.4),  # nothing to break
        ("NULL-SHA256", 7.4),
        ("ADH-AES256-SHA", 7.4),  # encrypted, but to whoever is in the middle
        ("DES-CBC-SHA", 5.9),  # breakable, still encrypted
        ("DES-CBC3-SHA", 5.9),
        ("IDEA-CBC-SHA", 5.9),
    ],
)
def test_score_separates_no_encryption_from_merely_broken(cipher_name, expected_score):
    vector = tls_check.cipher_cvss_vector(cipher_name) or catalog.FINDING_CATALOG["TLS-WEAK-CIPHER"].cvss_vector
    assert cvss.base_score(vector) == expected_score


@pytest.mark.parametrize(
    "cipher_name, reason_text",
    [
        ("DES-CBC-SHA", "56-bit key can be brute-forced"),  # single DES
        ("DES-CBC3-SHA", "SWEET32"),  # 3DES: a 64-bit block, a different weakness
        ("EXP-RC4-MD5", "export grade"),
        ("ADH-AES256-SHA", "authenticates neither side"),
        ("NULL-SHA", "does not encrypt"),
    ],
)
def test_the_finding_says_why_the_suite_is_weak(cipher_name, reason_text):
    findings = tls_check._weak_cipher_findings("https://t/", "t", 443, (cipher_name, "TLSv1.2", 56))
    (finding,) = findings
    assert finding.id == "TLS-WEAK-CIPHER"
    assert cipher_name in finding.evidence
    assert reason_text in finding.description


def test_no_finding_for_a_modern_suite():
    modern = ("ECDHE-RSA-AES256-GCM-SHA384", "TLSv1.3", 256)
    assert tls_check._weak_cipher_findings("https://t/", "t", 443, modern) == []
