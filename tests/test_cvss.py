"""FR-MODEL-03: CVSS v3.1 base score formula, checked against officially published examples."""

from __future__ import annotations

import pytest

from websec_scanner import cvss


@pytest.mark.parametrize(
    "vector, expected",
    [
        # Worst case on every metric (e.g. CVE-2021-44228 "Log4Shell" uses this exact vector).
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
        # Unauthenticated remote denial of service, no confidentiality/integrity impact.
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", 7.5),
        # Local, low-privilege full compromise (typical local-privilege-escalation vector).
        ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8),
        # Scope-changed, reflected-XSS-style vector from the CVSS v3.1 specification examples.
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),
        # No impact at all: base score is 0, not negative or undefined.
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0),
    ],
)
def test_base_score_matches_published_examples(vector, expected):
    assert cvss.base_score(vector) == expected


def test_score_is_never_above_ten():
    assert cvss.base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H") <= 10.0


@pytest.mark.parametrize(
    "bad_vector",
    [
        "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",  # missing "CVSS:3.1/" prefix
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H",  # missing A
        "CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",  # invalid AV value
        "",
    ],
)
def test_invalid_vectors_are_rejected(bad_vector):
    with pytest.raises(ValueError):
        cvss.base_score(bad_vector)


def test_parse_vector_returns_each_metric():
    metrics = cvss.parse_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    assert metrics == {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "H"}
