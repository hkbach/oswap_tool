"""FR-DET-04 (decision D7): the declarative table behind the TLS probes, rules/tls_probe.json.

Versions to try and weak cipher groups to offer are data, not code. These tests keep that data
honest without a network: the suite names must agree with the group they sit in, no suite may be
in two groups, and the limits must leave room for the probes the file asks for.
"""

from __future__ import annotations

import copy
import json

import pytest

from websec_scanner import rule_loader
from websec_scanner.checks import tls_probe

RULES = rule_loader.load_tls_probe()
SOURCE = rule_loader.RULES_DIR / "tls_probe.json"
PROBED = [g for g in RULES.groups if g.suites]

# How each probed group is recognised in an IANA suite name (the first group that matches wins,
# so the order of the file is the order of severity). Mirrors how the file was generated.
CLASSIFIERS = {
    "NULL": lambda n: "_WITH_NULL_" in n,
    "EXPORT": lambda n: "EXPORT" in n,
    "ANON": lambda n: "_anon_" in n,
    "RC4": lambda n: "_RC4_" in n,
    "3DES": lambda n: "3DES_EDE" in n,
    "DES": lambda n: "_DES_CBC_" in n and "3DES" not in n,
}


def test_the_rules_are_versioned_and_reported():
    assert RULES.version.strip()
    assert f"tls_probe={RULES.version}" in rule_loader.rules_version()


def test_the_protocols_are_the_five_the_decision_names():
    assert [p.name for p in RULES.protocols] == ["SSLv3", "TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3"]
    assert [p.version for p in RULES.protocols] == [0x0300, 0x0301, 0x0302, 0x0303, 0x0304]
    assert [p.weak for p in RULES.protocols] == [True, True, True, False, False]


def test_the_probed_groups_are_the_six_the_decision_names():
    assert [g.id for g in PROBED] == ["NULL", "EXPORT", "ANON", "RC4", "3DES", "DES"]


def test_groups_without_probes_still_classify_a_negotiated_suite():
    assert [g.id for g in RULES.groups if not g.suites] == ["RC2", "IDEA", "MD5"]


def test_group_ids_are_unique_and_reasons_are_known():
    ids = [g.id for g in RULES.groups]
    assert len(ids) == len(set(ids))
    assert {g.reason for g in RULES.groups} <= {"no-encryption", "unauthenticated", "broken"}
    assert all(g.description.strip() for g in RULES.groups)


def test_the_limits_leave_room_for_every_probe_and_the_two_existing_handshakes():
    probes = len(RULES.protocols) + len(PROBED)
    assert probes == 11
    assert RULES.max_connections >= probes + 2
    assert RULES.max_connections <= 30  # the ceiling D7 states
    assert 0 <= RULES.pause_seconds <= 5
    assert 1 <= RULES.probe_timeout_seconds <= 30  # caps one silent probe, whatever --timeout says


@pytest.mark.parametrize("group", PROBED, ids=lambda g: g.id)
def test_every_suite_name_agrees_with_its_group(group):
    classify = CLASSIFIERS[group.id]
    earlier = [CLASSIFIERS[g.id] for g in PROBED[: PROBED.index(group)]]
    for suite in group.suites:
        assert classify(suite.name), f"{suite.name} does not belong in {group.id}"
        assert not any(other(suite.name) for other in earlier), f"{suite.name} also matches an earlier group"


def test_no_suite_is_in_two_groups_and_codes_are_unique():
    codes = [s.code for g in RULES.groups for s in g.suites]
    assert len(codes) == len(set(codes))


def test_suites_are_real_registered_values_not_signalling_ones():
    for group in PROBED:
        for suite in group.suites:
            assert suite.name.startswith("TLS_")
            assert 0 <= suite.code <= 0xFFFF
            assert suite.code not in (0x00FF, 0x5600), "SCSV values are not suites"
            assert suite.code & 0x0F0F != 0x0A0A, "GREASE values are not suites"
            assert not 0x1301 <= suite.code <= 0x1305, "TLS 1.3 suites are not weak"


def test_a_probe_hello_fits_in_one_small_record():
    for group in PROBED:
        hello = tls_probe.group_hello(group, "scanner.example")
        assert len(hello) < 1400, f"{group.id}: {len(hello)} bytes would not fit one TCP segment"


@pytest.mark.parametrize("protocol", RULES.protocols, ids=lambda p: p.name)
def test_every_protocol_offers_suites_it_can_actually_use(protocol):
    assert protocol.probe_suites and len(protocol.probe_suites) == len(set(protocol.probe_suites))
    if protocol.name == "TLSv1.3":
        assert all(0x1301 <= c <= 0x1305 for c in protocol.probe_suites)
    else:
        assert not any(0x1301 <= c <= 0x1305 for c in protocol.probe_suites)


# --- negotiated suite name -> group (OpenSSL spelling, what ssl.cipher() returns) -----------------

GROUP_OF = {
    "NULL-SHA256": "NULL",
    "ECDHE-RSA-NULL-SHA": "NULL",
    "EXP-RC4-MD5": "EXPORT",
    "EXP-DES-CBC-SHA": "EXPORT",
    "EXP1024-DES-CBC-SHA": "EXPORT",
    "TLS_RSA_EXPORT_WITH_RC4_40_MD5": "EXPORT",
    "EXP-RC2-CBC-MD5": "EXPORT",  # export beats the RC2 reason
    "ADH-AES256-SHA": "ANON",
    "AECDH-AES128-SHA": "ANON",
    "ECDHE-RSA-RC4-SHA": "RC4",
    "RC4-MD5": "RC4",
    "DES-CBC3-SHA": "3DES",  # 3DES must win over the shorter DES marker
    "ECDHE-RSA-DES-CBC3-SHA": "3DES",
    "DES-CBC-SHA": "DES",
    "RC2-CBC-MD5": "RC2",
    "IDEA-CBC-SHA": "IDEA",
    "ECDHE-RSA-AES256-GCM-SHA384": None,
    "ECDHE-RSA-CHACHA20-POLY1305": None,
    "TLS_AES_128_GCM_SHA256": None,
}


@pytest.mark.parametrize("name, expected", sorted(GROUP_OF.items()))
def test_a_negotiated_suite_maps_to_its_group(name, expected):
    group = rule_loader.cipher_group_of(name)
    assert (group.id if group else None) == expected


# --- the loader is strict -------------------------------------------------------------------------


def _mutated(tmp_path, change):
    data = json.loads(SOURCE.read_text(encoding="utf-8"))
    change(data)
    path = tmp_path / "tls_probe.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def _group(data, group_id):
    return next(g for g in data["cipher_groups"] if g["id"] == group_id)


@pytest.mark.parametrize(
    "change, message",
    [
        (lambda d: d.pop("version"), "version"),
        (lambda d: d.__setitem__("protocols", []), "protocols"),
        (lambda d: d["protocols"].append(copy.deepcopy(d["protocols"][0])), "duplicate protocol"),
        (lambda d: d["protocols"][0].__setitem__("weak", "yes"), "weak"),
        (lambda d: d["protocols"][0].__setitem__("probe_suites", []), "probe_suites"),
        (lambda d: d["protocols"][0].__setitem__("version", "0xZZZZ"), "version"),
        (lambda d: d["cipher_groups"].append(copy.deepcopy(d["cipher_groups"][0])), "duplicate group"),
        (lambda d: _group(d, "RC4").__setitem__("reason", "scary"), "reason"),
        (lambda d: _group(d, "RC4")["suites"][0].__setitem__("code", "0x12"), "code"),
        (lambda d: _group(d, "DES")["suites"].append(copy.deepcopy(_group(d, "RC4")["suites"][0])), "two groups"),
        (lambda d: d["limits"].__setitem__("max_connections", 5), "cover"),
        (lambda d: d["limits"].__setitem__("max_connections", 500), "ceiling"),
        (lambda d: d["limits"].__setitem__("pause_seconds", -1), "pause_seconds"),
        (lambda d: d["limits"].__setitem__("probe_timeout_seconds", 0), "probe_timeout_seconds"),
        (lambda d: _group(d, "NULL").__setitem__("markers", []), "markers"),
    ],
)
def test_a_bad_file_is_refused_with_the_reason(tmp_path, change, message):
    with pytest.raises(ValueError, match=message):
        rule_loader._parse_tls_probe(_mutated(tmp_path, change))
