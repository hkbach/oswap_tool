"""CVSS v3.1 base score, computed from a vector string (FR-MODEL-03).

Implements the official base metric equations from the CVSS v3.1 specification
(first.org). Every score this module produces is a generic, estimated score for a
*type* of finding, not an assessment of a specific target: see ``catalog.FINDING_CATALOG``
and the "estimated" wording every report attaches to it (NFR-COMP-01, FR-RPT-08).
"""

from __future__ import annotations

import math
import re

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.50}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"N": 0.0, "L": 0.22, "H": 0.56}

_VECTOR_RE = re.compile(
    r"^CVSS:3\.1/AV:(?P<AV>[NALP])/AC:(?P<AC>[LH])/PR:(?P<PR>[NLH])/UI:(?P<UI>[NR])/"
    r"S:(?P<S>[UC])/C:(?P<C>[NLH])/I:(?P<I>[NLH])/A:(?P<A>[NLH])$"
)


def _roundup(value: float) -> float:
    """CVSS v3.1 Roundup(): round up to the nearest 0.1, using the spec's integer method
    to avoid binary floating-point error (e.g. plain ``round(7.0001, 1)`` can round down)."""
    int_value = round(value * 100000)
    if int_value % 10000 == 0:
        return int_value / 100000.0
    return (math.floor(int_value / 10000) + 1) / 10.0


def parse_vector(vector: str) -> dict[str, str]:
    """Parse a ``CVSS:3.1/AV:.../...`` vector string. Raises ValueError if malformed."""
    match = _VECTOR_RE.match(vector)
    if not match:
        raise ValueError(f"not a valid CVSS v3.1 vector: {vector!r}")
    return match.groupdict()


def base_score(vector: str) -> float:
    """CVSS v3.1 Base Score for ``vector`` (e.g. ``"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"``)."""
    metrics = parse_vector(vector)
    scope_changed = metrics["S"] == "C"
    pr_table = _PR_CHANGED if scope_changed else _PR_UNCHANGED

    c, i, a = _CIA[metrics["C"]], _CIA[metrics["I"]], _CIA[metrics["A"]]
    iss = 1 - (1 - c) * (1 - i) * (1 - a)
    impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if scope_changed else 6.42 * iss
    if impact <= 0:
        return 0.0

    exploitability = 8.22 * _AV[metrics["AV"]] * _AC[metrics["AC"]] * pr_table[metrics["PR"]] * _UI[metrics["UI"]]
    combined = 1.08 * (impact + exploitability) if scope_changed else impact + exploitability
    return _roundup(min(combined, 10.0))
