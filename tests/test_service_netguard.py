"""Which addresses a hosted scan may connect to (decision D12), and where results are stored.

Nothing here needs FastAPI, and nothing opens a connection: names are resolved by a fake resolver, or are addresses.
"""

from __future__ import annotations

import socket
import time

import pytest

from websec_scanner.service import ids, netguard, storage

PUBLIC = [
    "8.8.8.8",
    "1.1.1.1",
    "93.184.216.34",
    "172.15.255.255",  # just below 172.16.0.0/12
    "172.32.0.1",  # just above it
    "192.167.1.1",
    "11.0.0.1",
    "100.63.255.255",  # just below the shared range 100.64.0.0/10
    "100.128.0.1",  # just above it
    "2606:4700:4700::1111",
    "2001:4860:4860::8888",
    "::ffff:8.8.8.8",  # an IPv4 address in disguise is judged as the IPv4 address
]
NOT_PUBLIC = [
    "127.0.0.1",
    "127.255.255.255",
    "10.0.0.1",
    "10.255.255.255",
    "172.16.0.1",
    "172.31.255.255",
    "192.168.1.1",
    "169.254.169.254",  # the cloud metadata address
    "169.254.0.1",
    "100.64.0.1",  # carrier-grade NAT
    "100.127.255.255",
    "0.0.0.0",  # noqa: S104 - an address under test, not a bind
    "255.255.255.255",
    "224.0.0.1",
    "239.255.255.255",
    "240.0.0.1",
    "192.0.2.1",  # documentation ranges
    "198.51.100.1",
    "203.0.113.1",
    "198.18.0.1",  # benchmarking
    "::1",
    "::",
    "fe80::1",
    "fe80::1%12",  # with a scope id
    "fc00::1",
    "fd00:ec2::254",  # the IPv6 metadata address
    "ff02::1",
    "ff0e::1",  # global-scope multicast
    "::ffff:127.0.0.1",
    "::ffff:10.0.0.1",
    "::ffff:169.254.169.254",
    "64:ff9b::7f00:1",  # NAT64 of 127.0.0.1
    "64:ff9b::808:808",  # NAT64 of a public address: still refused, the gateway is not ours to trust
    "2002:7f00:1::",  # 6to4 of 127.0.0.1
    "2001:0:4136:e378:8000:63bf:3fff:fdd2",  # Teredo
    "2001:db8::1",
    "not-an-ip",
    "",
    "999.1.1.1",
    "1.2.3",
    "1.2.3.4.5",
    "0x7f.0.0.1",
    " 8.8.8.8",
    "8.8.8.8 ",
    "8.8.8.8/32",
]


@pytest.mark.parametrize("ip", PUBLIC)
def test_a_public_address_is_allowed(ip):
    assert netguard.is_public_address(ip) is True


@pytest.mark.parametrize("ip", NOT_PUBLIC)
def test_anything_else_is_refused(ip):
    assert netguard.is_public_address(ip) is False


def test_the_guard_for_the_core_is_the_public_check_unless_private_targets_are_allowed():
    assert netguard.make_guard(False) is netguard.is_public_address
    assert netguard.make_guard(True) is None


# --- the target ------------------------------------------------------------------------------------------------------


def resolver_for(mapping: dict[str, list[str]], seen: list | None = None):
    def resolve(host, port, type=None):  # noqa: A002 - the name of getaddrinfo's own keyword
        if seen is not None:
            seen.append((host, port, type))
        if host not in mapping:
            raise socket.gaierror(socket.EAI_NONAME, "Name or service not known")
        return [
            (socket.AF_INET6 if ":" in ip else socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, port))
            for ip in mapping[host]
        ]

    return resolve


def test_a_target_that_resolves_to_public_addresses_is_accepted():
    seen: list = []
    addresses = netguard.check_target(
        "https://shop.example/",
        resolver=resolver_for({"shop.example": ["93.184.216.34", "2606:4700:4700::1111"]}, seen),
    )
    assert addresses == ["93.184.216.34", "2606:4700:4700::1111"]
    assert seen == [("shop.example", 443, socket.SOCK_STREAM)]


@pytest.mark.parametrize(
    ("url", "port"),
    [
        ("http://a.example/", 80),
        ("https://a.example/", 443),
        ("http://a.example:8080/x", 8080),
        ("https://a.example:8443/", 8443),
    ],
)
def test_the_port_that_is_resolved_for_is_the_one_the_scan_will_use(url, port):
    seen: list = []
    netguard.check_target(url, resolver=resolver_for({"a.example": ["8.8.8.8"]}, seen))
    assert seen[0][1] == port


def test_one_internal_address_among_public_ones_refuses_the_target():
    resolver = resolver_for({"mixed.example": ["8.8.8.8", "10.0.0.5"]})
    with pytest.raises(netguard.TargetNotAllowed):
        netguard.check_target("http://mixed.example/", resolver=resolver)


@pytest.mark.parametrize(
    "ip", ["127.0.0.1", "10.1.2.3", "169.254.169.254", "192.168.0.1", "::1", "fd00::1", "::ffff:127.0.0.1"]
)
def test_a_name_that_resolves_to_an_internal_address_is_refused(ip):
    with pytest.raises(netguard.TargetNotAllowed) as raised:
        netguard.check_target("http://internal.example/", resolver=resolver_for({"internal.example": [ip]}))
    assert ip not in raised.value.detail and raised.value.code == "target_not_allowed"


def test_a_name_that_does_not_resolve_is_unresolvable():
    with pytest.raises(netguard.TargetUnresolvable) as raised:
        netguard.check_target("http://nope.example/", resolver=resolver_for({}))
    assert raised.value.code == "target_unresolvable"


def test_a_resolver_that_gives_nothing_is_unresolvable():
    with pytest.raises(netguard.TargetUnresolvable):
        netguard.check_target("http://empty.example/", resolver=lambda host, port, type=None: [])


def test_a_name_the_resolver_cannot_encode_is_unresolvable_not_a_crash():
    def refuse(host, port, type=None):  # noqa: A002
        raise UnicodeError("label empty or too long")

    with pytest.raises(netguard.TargetUnresolvable):
        netguard.check_target("http://" + "a" * 70 + ".example/", resolver=refuse)


def test_a_resolver_that_hangs_is_given_up_on():
    started = time.monotonic()

    def hang(host, port, type=None):  # noqa: A002
        time.sleep(2)
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", port))]

    with pytest.raises(netguard.TargetUnresolvable):
        netguard.check_target("http://slow.example/", resolver=hang, timeout=0.1)
    assert time.monotonic() - started < 1.5


def test_a_url_without_a_host_is_refused():
    for url in ("http:///path", "https://", "http://:80/"):
        with pytest.raises(netguard.TargetError) as raised:
            netguard.check_target(url, resolver=resolver_for({}))
        assert type(raised.value) is netguard.TargetError  # refused as malformed, before any lookup was tried


def test_an_impossible_port_is_refused():
    with pytest.raises(netguard.TargetError):
        netguard.check_target("http://a.example:99999/", resolver=resolver_for({"a.example": ["8.8.8.8"]}))


@pytest.mark.parametrize(
    "host",
    [
        "localhost",
        "127.0.0.1",
        "127.1",  # short forms of an address
        "2130706433",  # 127.0.0.1 as one number
        "0x7f000001",
        "0177.0.0.1",
        "0",
        "[::1]",
        "[::ffff:127.0.0.1]",
        "169.254.169.254",
        "[fd00:ec2::254]",
        "10.0.0.1",
        "192.168.1.1",
    ],
)
def test_the_real_resolver_never_lets_an_internal_address_through_however_it_is_written(host):
    """Whatever the operating system makes of this spelling, the answer is a refusal, never an acceptance."""
    with pytest.raises(netguard.TargetError):
        netguard.check_target(f"http://{host}/")


def test_an_address_literal_that_is_public_is_accepted_without_a_lookup():
    assert netguard.check_target("https://8.8.8.8/") == ["8.8.8.8"]


def test_userinfo_in_a_target_is_recognised():
    for url in (
        "http://user:pw@a.example/",
        "https://token@a.example/",
        "http://@a.example/",
        "https://u:@a.example:8443/x",
        "user:pw@a.example",  # no scheme: still a credential
        "token@a.example",
        "  user:pw@a.example ",
    ):
        assert netguard.has_userinfo(url) is True
    for url in (
        "http://a.example/",
        "https://a.example/path@x",
        "http://a.example/?next=a@b",
        "http://a.example:80/",
        "a.example",
        "a.example/x@y",
    ):
        assert netguard.has_userinfo(url) is False


# --- where results are stored ------------------------------------------------------------------------------------


AGENCY, CLIENT = ids.new_id("agency"), ids.new_id("client")


def scan_at(when_ms: int) -> str:
    return ids.new_id("scan", now_ms=when_ms)


def test_a_result_is_filed_by_agency_client_year_and_month_of_the_scan_id(tmp_path):
    scan_id = scan_at(1_791_100_000_000)  # 2026-10-04 UTC
    relative = storage.write_report(tmp_path, AGENCY, CLIENT, scan_id, b'{"a": 1}')
    assert relative == f"{AGENCY}/{CLIENT}/2026/10/{scan_id}.json"
    assert (tmp_path / relative).read_bytes() == b'{"a": 1}'
    assert storage.read_report(tmp_path, relative) == b'{"a": 1}'


def test_the_month_comes_from_utc_not_from_the_local_clock(tmp_path):
    edge = scan_at(1_793_491_199_999)  # 2026-10-31T23:59:59.999Z
    after = scan_at(1_793_491_200_000)  # 2026-11-01T00:00:00Z
    assert storage.relative_path(AGENCY, CLIENT, edge).split("/")[2:4] == ["2026", "10"]
    assert storage.relative_path(AGENCY, CLIENT, after).split("/")[2:4] == ["2026", "11"]


@pytest.mark.parametrize(
    "bad",
    [
        ("../" + "a" * 26, CLIENT, scan_at(1)),
        (AGENCY, "../../etc", scan_at(1)),
        (AGENCY, CLIENT, "scn_../../x"),
        (CLIENT, CLIENT, scan_at(1)),  # an id of the wrong kind
        (AGENCY, AGENCY, scan_at(1)),
        (AGENCY, CLIENT, ids.new_id("client")),
        ("", CLIENT, scan_at(1)),
        (AGENCY, CLIENT, ""),
    ],
)
def test_a_path_is_only_made_from_ids_of_the_right_kinds(tmp_path, bad):
    with pytest.raises(storage.StorageError):
        storage.write_report(tmp_path, *bad, b"x")
    assert list(tmp_path.rglob("*")) == []  # nothing was made


def test_a_stored_path_that_leaves_the_folder_is_never_read(tmp_path):
    (tmp_path.parent / "secret.txt").write_text("outside", encoding="utf-8")
    for relative in ("../secret.txt", "../../secret.txt", "a/../../secret.txt"):
        with pytest.raises(storage.StorageError):
            storage.read_report(tmp_path / "results", relative)
    (tmp_path / "results").mkdir()
    with pytest.raises(storage.StorageError):
        storage.read_report(tmp_path / "results", "../secret.txt")


def test_no_half_written_file_is_ever_visible_and_no_temporary_one_is_left(tmp_path, monkeypatch):
    scan_id = scan_at(1_791_100_000_000)
    seen_during = []
    real_replace = storage.os.replace

    def watching_replace(source, destination):
        seen_during.append(sorted(p.name for p in (tmp_path / AGENCY / CLIENT / "2026" / "10").iterdir()))
        real_replace(source, destination)

    monkeypatch.setattr(storage.os, "replace", watching_replace)
    storage.write_report(tmp_path, AGENCY, CLIENT, scan_id, b"complete")
    assert len(seen_during[0]) == 1 and seen_during[0][0].startswith(
        ".tmp-"
    )  # only the temporary file, until the rename
    assert [p.name for p in (tmp_path / AGENCY / CLIENT / "2026" / "10").iterdir()] == [f"{scan_id}.json"]


def test_a_failed_write_leaves_nothing_behind(tmp_path, monkeypatch):
    scan_id = scan_at(1_791_100_000_000)

    def broken(source, destination):
        raise OSError("disk full")

    monkeypatch.setattr(storage.os, "replace", broken)
    with pytest.raises(OSError, match="disk full"):
        storage.write_report(tmp_path, AGENCY, CLIENT, scan_id, b"x")
    assert [p for p in tmp_path.rglob("*") if p.is_file()] == []


def test_writing_a_result_twice_replaces_it(tmp_path):
    scan_id = scan_at(1_791_100_000_000)
    storage.write_report(tmp_path, AGENCY, CLIENT, scan_id, b"first")
    relative = storage.write_report(tmp_path, AGENCY, CLIENT, scan_id, b"second")
    assert storage.read_report(tmp_path, relative) == b"second"
