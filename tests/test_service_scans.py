"""The scan endpoints of the agency API (decision D12, phase 2): request a scan, follow it, read its report.

Lifecycle, limits and isolation are tested with a fake scanner that can be held and released; a few tests run the real
scanner against a local site (a development setting lets it reach loopback; production refuses that, which is
tested too).
"""

from __future__ import annotations

import json
import logging
import sqlite3
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path

import jsonschema
import pytest
from crawl_site import Page, html, site_handler

pytest.importorskip("fastapi")
pytest.importorskip("httpx")

from fastapi.testclient import TestClient  # noqa: E402

from websec_scanner import catalog  # noqa: E402
from websec_scanner.crawler.crawl import CrawlOptions  # noqa: E402
from websec_scanner.models import SCHEMA_VERSION, ScannedPage, ScanResult  # noqa: E402
from websec_scanner.service import api, ids, netguard, openapi, storage  # noqa: E402
from websec_scanner.service.config import Settings  # noqa: E402
from websec_scanner.service.db import Repository  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
ALL = ["clients:read", "clients:write", "scans:read", "scans:write"]
PROBLEM = "application/problem+json"
ATTEST = {"confirmed": True, "statement_version": "v1"}


class Clock:
    def __init__(self):
        self.now = datetime(2026, 10, 5, 12, 0, 0, tzinfo=UTC)

    def __call__(self):
        return self.now

    def advance(self, **kwargs):
        self.now += timedelta(**kwargs)


class FakeScanner:
    """A stand-in for run_scan that records how it was called and can be held until the test lets it go."""

    def __init__(self):
        self.calls: list[dict] = []
        self.hold = False
        self.fail_with: Exception | None = None
        self.release = threading.Event()
        self.started = threading.Semaphore(0)
        self._lock = threading.Lock()
        self.active = 0
        self.max_active = 0
        self.active_hosts: list[str] = []
        self.overlapping_hosts = False

    def __call__(self, target, **kwargs):
        host = target.split("//", 1)[-1].split("/")[0].split(":")[0].lower()
        with self._lock:
            self.calls.append({"target": target, **kwargs})
            if host in self.active_hosts:
                self.overlapping_hosts = True
            self.active_hosts.append(host)
            self.active += 1
            self.max_active = max(self.max_active, self.active)
        self.started.release()
        try:
            if self.hold:
                assert self.release.wait(20), "the test never released the scan"
            if self.fail_with is not None:
                raise self.fail_with
            return self.result(target)
        finally:
            with self._lock:
                self.active -= 1
                self.active_hosts.remove(host)

    @staticmethod
    def result(target):
        result = ScanResult(
            target=target, started_at="2026-10-05T12:00:00.000Z", finished_at="2026-10-05T12:00:01.000Z"
        )
        result.baseline_fetched = True
        result.final_url = target
        result.pages = [ScannedPage(url=target, status=200, depth=0, checked=True, findings=0)]
        return result

    def wait_started(self, count=1):
        for _ in range(count):
            assert self.started.acquire(timeout=10), "the scan never started"


@pytest.fixture
def clock():
    return Clock()


@pytest.fixture
def scanner():
    fake = FakeScanner()
    yield fake
    fake.release.set()  # never leave a held scan thread behind


@pytest.fixture
def make_app(tmp_path, clock, scanner):
    def make(settings_changes=None, fake=True):
        defaults = {"allow_private_targets": True, "tls_probe": False}  # a local test site is on loopback
        settings = Settings(data_dir=tmp_path / "data", **{**defaults, **(settings_changes or {})})
        repo = Repository(settings.db_path, clock=clock)
        return api.create_app(settings, repo, scan_fn=scanner if fake else None)

    return make


@pytest.fixture
def app(make_app):
    return make_app()


class Agency:
    def __init__(self, app, name, scopes=ALL):
        repo = app.state.repo
        self.id = repo.create_agency(name)["agency_id"]
        self.record, self.key = repo.create_key(self.id, "backend", scopes)
        self.http = TestClient(app, headers={"Authorization": f"Bearer {self.key}"}, raise_server_exceptions=False)
        self.client_id = self.http.post("/v1/clients", json={"display_name": f"{name} client"}).json()["client_id"]

    def scan(self, target="http://site-a.example/", key=None, **extra):
        body = {"client_id": self.client_id, "target": target, "attestation": ATTEST, **extra}
        headers = {"Idempotency-Key": key} if key is not None else {}
        return self.http.post("/v1/scans", json=body, headers=headers)


@pytest.fixture
def a(app):
    return Agency(app, "Agency A")


@pytest.fixture
def b(app):
    return Agency(app, "Agency B")


def idle(app):
    assert app.state.runner.wait_idle(20), "the scans did not finish"


def problem(response, status, code):
    assert response.status_code == status, response.text
    assert response.headers["content-type"].startswith(PROBLEM)
    body = response.json()
    assert body["code"] == code and body["status"] == status
    return body


def strip_id(body: dict) -> dict:
    return {k: v for k, v in body.items() if k != "request_id"}


# --- requesting a scan ----------------------------------------------------------------------------


def test_a_scan_is_queued_and_answered_at_once(a, scanner):
    scanner.hold = True
    response = a.scan()
    assert response.status_code == 202
    body = response.json()
    assert ids.is_valid("scan", body["scan_id"]) and response.headers["location"] == f"/v1/scans/{body['scan_id']}"
    assert body["status"] == "queued" and body["client_id"] == a.client_id
    assert (
        body["created_at"] == "2026-10-05T12:00:00.000Z" and body["started_at"] is None and body["finished_at"] is None
    )
    assert body["summary"] is None and body["error"] is None and body["report_available"] is False
    assert body["crawl"] is False and body["checks"] == list(catalog.GROUP_IDS)


def test_the_scan_runs_in_the_background_and_completes(app, a, scanner, clock):
    response = a.scan()
    scan_id = response.json()["scan_id"]
    idle(app)
    body = a.http.get(f"/v1/scans/{scan_id}").json()
    assert body["status"] == "completed" and body["report_available"] is True and body["error"] is None
    assert body["started_at"] == body["finished_at"] == "2026-10-05T12:00:00.000Z"  # the frozen test clock
    assert body["summary"] == {
        "findings": 0,
        "severity": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0},
        "gate": {"fail_on": "high", "failed": False, "incomplete": False},
        "pages_scanned": 1,
    }
    assert len(scanner.calls) == 1


def test_the_scan_is_run_with_the_operators_limits_and_nothing_from_the_caller(app, a, scanner):
    a.scan(checks=["tls", "headers"], crawl=True)
    idle(app)
    call = scanner.calls[0]
    s = app.state.settings
    assert call["target"] == "http://site-a.example/"
    assert call["groups"] == ["headers", "tls"]  # the order of the documented table, not of the request
    assert (call["rate_limit"], call["max_requests"], call["max_duration"]) == (
        s.scan_rate_limit,
        s.scan_max_requests,
        s.scan_max_duration,
    )
    assert (call["timeout"], call["workers"], call["tls_probe"]) == (s.scan_timeout, s.scan_workers, s.tls_probe)
    assert call["crawl"] == s.crawl and isinstance(call["crawl"], CrawlOptions)
    assert set(call) == {
        "target", "timeout", "workers", "groups", "rate_limit", "max_requests", "max_duration", "tls_probe", "crawl",
        "connect_guard",
    }  # fmt: skip


def test_without_crawl_the_scan_gets_no_crawl_options(app, a, scanner):
    a.scan()
    a.scan(target="http://site-b.example/", crawl=False)
    idle(app)
    assert [c["crawl"] for c in scanner.calls] == [None, None]


def test_every_check_group_runs_when_none_are_named(app, a, scanner):
    a.scan()
    idle(app)
    assert scanner.calls[0]["groups"] == list(catalog.GROUP_IDS)


def test_the_scan_is_given_no_guard_when_private_targets_are_allowed(app, a, scanner):
    a.scan()
    idle(app)
    assert scanner.calls[0]["connect_guard"] is None


# --- what a request may contain -------------------------------------------------------------------


@pytest.mark.parametrize(
    ("change", "where"),
    [
        ({"attestation": None}, "attestation"),
        ({"attestation": {"confirmed": False, "statement_version": "v1"}}, "confirmed"),
        ({"attestation": {"confirmed": "true", "statement_version": "v1"}}, "confirmed"),
        ({"attestation": {"confirmed": 1, "statement_version": "v1"}}, "confirmed"),
        ({"attestation": {"confirmed": True}}, "statement_version"),
        ({"attestation": {"confirmed": True, "statement_version": ""}}, "statement_version"),
        ({"attestation": {"confirmed": True, "statement_version": "v1", "signed_by": "me"}}, "signed_by"),
        ({"target": ""}, "target"),
        ({"target": "x" * 2049}, "target"),
        ({"target": 5}, "target"),
        ({"checks": []}, "checks"),
        ({"checks": "headers"}, "checks"),
        ({"checks": [1]}, "checks"),
        ({"checks": ["headers"] * 17}, "checks"),
        ({"crawl": "yes"}, "crawl"),
        ({"crawl": 1}, "crawl"),
        ({"crawl": None}, "crawl"),
        ({"password": "p"}, "password"),
        ({"headers": {"Authorization": "x"}}, "headers"),
        ({"crawl_depth": 9}, "crawl_depth"),
        ({"ignore_robots": True}, "ignore_robots"),
        ({"show_secrets": True}, "show_secrets"),
        ({"rate_limit": 1000}, "rate_limit"),
        ({"max_requests": 10**6}, "max_requests"),
    ],
)
def test_an_invalid_request_is_a_422_that_says_where_and_queues_nothing(a, scanner, change, where):
    body = {"client_id": a.client_id, "target": "http://site-a.example/", "attestation": ATTEST, **change}
    body = {k: v for k, v in body.items() if not (k == "attestation" and v is None)}
    response = a.http.post("/v1/scans", json=body)
    errors = problem(response, 422, "validation_error")["errors"]
    assert any(where in [str(part) for part in e["loc"]] for e in errors), errors
    assert a.http.get("/v1/scans").json()["items"] == [] and scanner.calls == []


def test_the_client_id_is_required(a):
    body = {"target": "http://site-a.example/", "attestation": ATTEST}
    problem(a.http.post("/v1/scans", json=body), 422, "validation_error")


def test_a_422_never_echoes_what_was_sent(a):
    sentinel = "SENTINEL-SECRET-VALUE-77"
    for change in ({"password": sentinel}, {"crawl": sentinel}, {"checks": [sentinel]}, {"target": sentinel * 300}):
        body = {"client_id": a.client_id, "target": "http://site-a.example/", "attestation": ATTEST, **change}
        response = a.http.post("/v1/scans", json=body)
        assert response.status_code in (422,) and sentinel not in response.text, response.text


@pytest.mark.parametrize(
    "target", ["ftp://site-a.example/", "javascript:alert(1)", "file:///etc/passwd", "http://", "https:///x"]
)
def test_a_target_that_is_not_a_web_address_is_refused(a, target):
    problem(a.scan(target=target), 422, "invalid_target")


@pytest.mark.parametrize(
    "target",
    [
        "http://user:pass@site-a.example/",
        "https://token@site-a.example/",
        "user:pw@site-a.example",
        "http://@site-a.example/",
    ],
)
def test_a_target_with_a_user_name_or_password_is_refused_and_not_echoed(a, target):
    response = a.scan(target=target)
    problem(response, 422, "credential_not_accepted")
    assert "pass" not in response.text.replace("password", "") and "token@" not in response.text


def test_a_bare_host_name_is_accepted_and_made_into_an_https_url(app, a, scanner):
    a.scan(target="site-a.example")
    idle(app)
    assert scanner.calls[0]["target"] == "https://site-a.example/"


def test_an_unknown_check_group_is_refused_without_naming_it_back(a):
    response = a.scan(checks=["headers", "no-such-group-xyz"])
    problem(response, 422, "invalid_checks")
    assert "no-such-group-xyz" not in response.text


def test_a_statement_version_the_service_does_not_know_is_refused(a):
    response = a.http.post(
        "/v1/scans",
        json={
            "client_id": a.client_id,
            "target": "http://site-a.example/",
            "attestation": {"confirmed": True, "statement_version": "v9"},
        },
    )
    body = problem(response, 422, "unsupported_statement_version")
    assert "v1" in body["detail"]


def test_the_statement_versions_are_the_operators_to_set(make_app, scanner):
    app = make_app({"attestation_versions": ("v2", "v3")})
    agency = Agency(app, "Agency")
    problem(agency.scan(), 422, "unsupported_statement_version")
    ok = agency.http.post(
        "/v1/scans",
        json={
            "client_id": agency.client_id,
            "target": "http://site-a.example/",
            "attestation": {"confirmed": True, "statement_version": "v3"},
        },
    )
    assert ok.status_code == 202


# --- the target must be a public address ----------------------------------------------------------


@pytest.fixture
def strict(make_app, scanner):
    """An app as it runs in production: private and loopback targets are refused."""
    app = make_app({"allow_private_targets": False})
    return app, Agency(app, "Strict Agency")


@pytest.mark.parametrize(
    "target",
    [
        "http://127.0.0.1/",
        "http://localhost/",
        "http://[::1]/",
        "http://169.254.169.254/latest/meta-data/",
        "http://10.0.0.1/",
        "http://192.168.0.10:8080/",
        "https://[fd00:ec2::254]/",
        "http://[::ffff:127.0.0.1]/",
    ],
)
def test_an_internal_target_is_refused_before_anything_is_queued_or_sent(strict, scanner, target):
    app, agency = strict
    response = agency.scan(target=target)
    body = problem(response, 422, "target_not_allowed")
    assert not any(token in response.text for token in ("127.0.0.1", "169.254", "10.0.0.1", "192.168", "::1", "fd00"))
    assert "public" in body["detail"]
    assert agency.http.get("/v1/scans").json()["items"] == [] and scanner.calls == []


@pytest.mark.parametrize(
    "target", ["http://2130706433/", "http://0x7f000001/", "http://127.1/", "http://0177.0.0.1/", "http://0/"]
)
def test_an_internal_address_written_in_an_unusual_way_is_refused_too(strict, scanner, target):
    app, agency = strict
    response = agency.scan(target=target)
    assert response.status_code == 422 and response.json()["code"] in {
        "target_not_allowed",
        "invalid_target",
        "target_unresolvable",
    }
    assert agency.http.get("/v1/scans").json()["items"] == [] and scanner.calls == []


def test_a_name_that_does_not_resolve_is_a_422_not_a_server_error(strict, monkeypatch):
    app, agency = strict

    def nothing(url, **kwargs):
        raise netguard.TargetUnresolvable

    monkeypatch.setattr(netguard, "check_target", nothing)
    problem(agency.scan(target="http://no-such-host.invalid/"), 422, "target_unresolvable")


def test_a_public_target_is_accepted_and_scanned(strict, scanner, monkeypatch):
    app, agency = strict
    asked = []
    monkeypatch.setattr(netguard, "check_target", lambda url, **kw: asked.append(url) or ["93.184.216.34"])
    assert agency.scan(target="https://shop.example/").status_code == 202
    idle(app)
    assert asked == ["https://shop.example/"] and scanner.calls[0]["connect_guard"] is netguard.is_public_address


def test_the_dns_lookup_is_not_made_for_a_client_that_is_not_yours(strict, monkeypatch):
    app, agency = strict
    asked = []
    monkeypatch.setattr(netguard, "check_target", lambda url, **kw: asked.append(url) or ["93.184.216.34"])
    stranger = ids.new_id("client")
    response = agency.http.post(
        "/v1/scans", json={"client_id": stranger, "target": "http://x.example/", "attestation": ATTEST}
    )
    problem(response, 404, "not_found")
    assert asked == []


# --- who may see what -----------------------------------------------------------------------------


def test_a_scan_needs_a_key_and_the_right_scope(app, a):
    anon = TestClient(app, raise_server_exceptions=False)
    problem(anon.post("/v1/scans", json={}), 401, "unauthorized")
    problem(anon.get("/v1/scans"), 401, "unauthorized")
    problem(anon.get(f"/v1/scans/{ids.new_id('scan')}"), 401, "unauthorized")
    repo = app.state.repo
    reader = TestClient(app, headers={"Authorization": f"Bearer {repo.create_key(a.id, 'r', ['scans:read'])[1]}"})
    writer = TestClient(app, headers={"Authorization": f"Bearer {repo.create_key(a.id, 'w', ['scans:write'])[1]}"})
    body = {"client_id": a.client_id, "target": "http://site-a.example/", "attestation": ATTEST}
    problem(reader.post("/v1/scans", json=body), 403, "forbidden")
    scan_id = writer.post("/v1/scans", json=body).json()["scan_id"]
    problem(writer.get(f"/v1/scans/{scan_id}"), 403, "forbidden")
    problem(writer.get("/v1/scans"), 403, "forbidden")
    problem(writer.get(f"/v1/scans/{scan_id}/report"), 403, "forbidden")
    problem(writer.get(f"/v1/scans/{scan_id}/report.html"), 403, "forbidden")
    idle(app)
    assert (
        reader.get(f"/v1/scans/{scan_id}").status_code == 200
        and reader.get(f"/v1/scans/{scan_id}/report").status_code == 200
    )


def test_another_agency_sees_nothing_of_a_scan_in_any_way(app, a, b):
    scan_id = a.scan().json()["scan_id"]
    idle(app)
    unknown = ids.new_id("scan")
    for path in ("", "/report", "/report.html"):
        theirs = b.http.get(f"/v1/scans/{scan_id}{path}")
        nothing = b.http.get(f"/v1/scans/{unknown}{path}")
        assert strip_id(problem(theirs, 404, "not_found")) == strip_id(problem(nothing, 404, "not_found")), path
    assert b.http.get("/v1/scans").json() == {"items": [], "next_cursor": None}
    assert b.http.get("/v1/scans", params={"client_id": a.client_id}).json()["items"] == []
    assert a.http.get(f"/v1/scans/{scan_id}").status_code == 200  # untouched


def test_a_scan_cannot_be_requested_for_another_agencys_client(app, a, b):
    body = {"client_id": a.client_id, "target": "http://site-a.example/", "attestation": ATTEST}
    theirs = b.http.post("/v1/scans", json=body)
    nothing = b.http.post("/v1/scans", json={**body, "client_id": ids.new_id("client")})
    assert strip_id(problem(theirs, 404, "not_found")) == strip_id(problem(nothing, 404, "not_found"))
    assert a.http.get("/v1/scans").json()["items"] == []


def test_a_deleted_client_cannot_have_a_new_scan_but_keeps_its_old_ones(app, a):
    scan_id = a.scan().json()["scan_id"]
    idle(app)
    a.http.delete(f"/v1/clients/{a.client_id}")
    problem(a.scan(), 404, "not_found")
    assert a.http.get(f"/v1/scans/{scan_id}").json()["status"] == "completed"


def test_a_suspended_agency_cannot_use_its_key_for_scans_either(app, a):
    app.state.repo.set_agency_status(a.id, "suspended")
    problem(a.scan(), 401, "unauthorized")
    problem(a.http.get("/v1/scans"), 401, "unauthorized")


# --- retrying safely ------------------------------------------------------------------------------


def test_the_same_idempotency_key_and_body_gives_back_the_first_scan(app, a, scanner):
    first = a.scan(key="order-1001")
    again = a.scan(key="order-1001")
    assert first.status_code == again.status_code == 202
    assert again.json()["scan_id"] == first.json()["scan_id"] and "idempotent-replayed" not in first.headers
    assert again.headers["idempotent-replayed"] == "true"
    assert again.headers["location"] == first.headers["location"]
    idle(app)
    assert len(scanner.calls) == 1 and len(a.http.get("/v1/scans").json()["items"]) == 1


def test_a_replay_after_the_scan_finished_shows_its_current_state(app, a):
    scan_id = a.scan(key="k1").json()["scan_id"]
    idle(app)
    replay = a.scan(key="k1").json()
    assert replay["scan_id"] == scan_id and replay["status"] == "completed"


def test_the_same_key_with_a_different_body_is_a_conflict(app, a, scanner):
    a.scan(key="k1")
    for change in ({"target": "http://other.example/"}, {"crawl": True}, {"checks": ["headers"]}):
        problem(a.scan(key="k1", **change), 409, "idempotency_key_reused")
    idle(app)
    assert len(scanner.calls) == 1


def test_two_ways_of_writing_the_same_target_are_the_same_request(app, a, scanner):
    first = a.scan(target="http://Site-A.example", key="k1")
    again = a.scan(target="http://site-a.example/", key="k1")
    assert again.json()["scan_id"] == first.json()["scan_id"]


def test_the_order_of_the_checks_does_not_make_a_different_request(app, a):
    first = a.scan(checks=["tls", "headers"], key="k1")
    again = a.scan(checks=["headers", "tls"], key="k1")
    assert again.json()["scan_id"] == first.json()["scan_id"]


def test_two_agencies_may_use_the_same_key(app, a, b):
    one, two = a.scan(key="same"), b.scan(key="same")
    assert one.status_code == two.status_code == 202 and one.json()["scan_id"] != two.json()["scan_id"]


def test_a_key_is_forgotten_after_a_day(app, a, clock):
    first = a.scan(key="k1").json()["scan_id"]
    clock.advance(hours=23, minutes=59)
    assert a.scan(key="k1").json()["scan_id"] == first
    clock.advance(minutes=2)
    assert a.scan(key="k1").json()["scan_id"] != first


@pytest.mark.parametrize("key", ["has space", "a" * 65, "a/b", "a;b", "a=b", "<script>"])
def test_a_bad_idempotency_key_is_refused(a, scanner, key):
    problem(a.scan(key=key), 422, "validation_error")
    assert scanner.calls == [] and a.http.get("/v1/scans").json()["items"] == []


def test_the_longest_allowed_idempotency_key_works(a):
    assert a.scan(key="k" * 64).status_code == 202


def test_requests_that_arrive_together_with_one_key_queue_exactly_one_scan(app, a, scanner):
    body = {"client_id": a.client_id, "target": "http://site-a.example/", "attestation": ATTEST}

    def send(_):
        return a.http.post("/v1/scans", json=body, headers={"Idempotency-Key": "burst"}).json()["scan_id"]

    with ThreadPoolExecutor(8) as pool:
        seen = set(pool.map(send, range(8)))
    idle(app)
    assert len(seen) == 1 and len(scanner.calls) == 1


# --- limits ---------------------------------------------------------------------------------------


def running(app):
    return app.state.repo.count_scans("running")


def test_only_so_many_scans_run_at_once_and_the_rest_wait_their_turn(make_app, scanner):
    app = make_app({"max_concurrent_scans": 2, "max_concurrent_per_agency": 2})
    agency = Agency(app, "A")
    scanner.hold = True
    ids_ = [agency.scan(target=f"http://site-{n}.example/").json()["scan_id"] for n in range(4)]
    scanner.wait_started(2)
    assert running(app) == 2 and app.state.repo.count_scans("queued") == 2
    assert [agency.http.get(f"/v1/scans/{i}").json()["status"] for i in ids_] == [
        "running",
        "running",
        "queued",
        "queued",
    ]
    scanner.release.set()
    idle(app)
    assert scanner.max_active == 2 and app.state.repo.count_scans("completed") == 4


def test_one_agency_cannot_take_every_slot(make_app, scanner):
    app = make_app({"max_concurrent_scans": 4, "max_concurrent_per_agency": 1})
    one, two = Agency(app, "One"), Agency(app, "Two")
    scanner.hold = True
    for n in range(3):
        one.scan(target=f"http://one-{n}.example/")
    two.scan(target="http://two-0.example/")
    scanner.wait_started(2)
    states = {a.id: [s["status"] for s in app.state.repo.list_scans(a.id, limit=10)] for a in (one, two)}
    assert sorted(states[one.id]) == ["queued", "queued", "running"] and states[two.id] == ["running"]
    scanner.release.set()
    idle(app)
    assert scanner.max_active == 2


def test_two_scans_of_the_same_host_never_run_together_but_other_hosts_do(make_app, scanner):
    app = make_app({"max_concurrent_scans": 4, "max_concurrent_per_agency": 4})
    agency = Agency(app, "A")
    scanner.hold = True
    agency.scan(target="http://same.example/one")
    agency.scan(target="http://SAME.example/two")
    agency.scan(target="https://same.example:8443/three")
    agency.scan(target="http://other.example/")
    scanner.wait_started(2)
    assert running(app) == 2 and app.state.repo.count_scans("queued") == 2
    scanner.release.set()
    idle(app)
    assert scanner.overlapping_hosts is False and app.state.repo.count_scans("completed") == 4


def test_the_queue_is_bounded_in_total_and_per_agency(make_app, scanner):
    app = make_app(
        {"max_concurrent_scans": 1, "max_concurrent_per_agency": 1, "max_queued_scans": 3, "max_queued_per_agency": 2}
    )
    one, two = Agency(app, "One"), Agency(app, "Two")
    scanner.hold = True
    one.scan(target="http://run.example/")  # runs, so it does not count as waiting
    scanner.wait_started()
    assert one.scan(target="http://q1.example/").status_code == 202
    assert one.scan(target="http://q2.example/").status_code == 202
    full = one.scan(target="http://q3.example/")  # a third waiting scan for this agency
    problem(full, 429, "queue_full")
    assert full.headers["retry-after"] == "30"
    assert two.scan(target="http://q4.example/").status_code == 202  # the other agency still has room
    problem(two.scan(target="http://q5.example/"), 429, "queue_full")  # now the whole queue is full
    scanner.release.set()
    idle(app)
    assert app.state.repo.count_scans("queued") == 0


def test_a_refused_request_leaves_nothing_in_the_queue_and_no_idempotency_key(make_app, scanner):
    app = make_app(
        {"max_concurrent_scans": 1, "max_concurrent_per_agency": 1, "max_queued_scans": 1, "max_queued_per_agency": 1}
    )
    agency = Agency(app, "A")
    scanner.hold = True
    agency.scan(target="http://run.example/")
    scanner.wait_started()
    agency.scan(target="http://q1.example/")
    problem(agency.scan(target="http://q2.example/", key="retry-me"), 429, "queue_full")
    scanner.release.set()
    idle(app)
    again = agency.scan(target="http://q2.example/", key="retry-me")  # the key was not used up by the refusal
    assert again.status_code == 202 and "idempotent-replayed" not in again.headers


# --- when a scan breaks, and when the service stops -----------------------------------------------


def test_a_scan_that_breaks_is_failed_without_taking_anything_else_down(app, a, scanner, caplog):
    caplog.set_level(logging.ERROR, logger="websec_scanner.service")
    scanner.fail_with = RuntimeError("could not read http://site-a.example/?token=SECRETVALUE99 at all")
    broken = a.scan(target="http://site-a.example/?token=SECRETVALUE99").json()["scan_id"]
    idle(app)
    scanner.fail_with = None
    fine = a.scan(target="http://site-b.example/").json()["scan_id"]
    idle(app)
    body = a.http.get(f"/v1/scans/{broken}").json()
    assert body["status"] == "failed" and body["error"]["code"] == "scan_error" and body["summary"] is None
    assert "SECRETVALUE99" not in json.dumps(body) and body["report_available"] is False
    assert a.http.get(f"/v1/scans/{fine}").json()["status"] == "completed"
    assert "SECRETVALUE99" not in caplog.text and broken in caplog.text  # the operator's log is redacted too


def test_a_failed_scan_has_no_report_and_says_so(app, a, scanner):
    scanner.fail_with = RuntimeError("x")
    scan_id = a.scan().json()["scan_id"]
    idle(app)
    problem(a.http.get(f"/v1/scans/{scan_id}/report"), 409, "scan_failed")
    problem(a.http.get(f"/v1/scans/{scan_id}/report.html"), 409, "scan_failed")


def test_a_scan_that_cannot_write_its_result_is_failed_too(app, a, scanner, monkeypatch):
    monkeypatch.setattr(storage, "write_report", lambda *args, **kwargs: (_ for _ in ()).throw(OSError("disk full")))
    scan_id = a.scan().json()["scan_id"]
    idle(app)
    assert a.http.get(f"/v1/scans/{scan_id}").json()["status"] == "failed"


def test_a_service_that_stopped_mid_scan_fails_it_on_the_next_start_and_resumes_the_queue(make_app, scanner, tmp_path):
    app = make_app()
    agency = Agency(app, "A")
    repo = app.state.repo
    common = {
        "checks": list(catalog.GROUP_IDS),
        "crawl": False,
        "statement_version": "v1",
        "idempotency_key": None,
        "body_hash": "x",
        "max_queued": 10,
        "max_queued_per_agency": 10,
        "idempotency_ttl_seconds": 60,
    }
    interrupted, _ = repo.create_scan(
        agency.id, agency.client_id, target="http://old.example/", target_host="old.example", **common
    )
    repo.mark_running(interrupted["scan_id"])  # the service stopped here
    waiting, _ = repo.create_scan(
        agency.id, agency.client_id, target="http://waiting.example/", target_host="waiting.example", **common
    )
    restarted = api.create_app(app.state.settings, repo, scan_fn=scanner)  # the next start
    assert restarted.state.runner.wait_idle(20)
    after = {s["scan_id"]: s for s in repo.list_scans(agency.id, limit=10)}
    assert (
        after[interrupted["scan_id"]]["status"] == "failed"
        and after[interrupted["scan_id"]]["error_code"] == "interrupted"
    )
    assert after[waiting["scan_id"]]["status"] == "completed"
    again = agency.http.get(f"/v1/scans/{interrupted['scan_id']}").json()
    assert again["error"]["code"] == "interrupted" and "stopped" in again["error"]["detail"]


# --- reading a result -----------------------------------------------------------------------------


@pytest.fixture(scope="module")
def report_validator():
    schema = json.loads((ROOT / "docs" / "report.schema.json").read_text(encoding="utf-8"))
    return jsonschema.Draft202012Validator(schema)


def test_the_report_cannot_be_read_before_the_scan_has_finished(make_app, scanner):
    app = make_app()
    agency = Agency(app, "A")
    scanner.hold = True
    scan_id = agency.scan().json()["scan_id"]
    for path in ("/report", "/report.html"):  # queued or already running, the answer is the same
        problem(agency.http.get(f"/v1/scans/{scan_id}{path}"), 409, "scan_not_finished")
    scanner.wait_started()
    problem(agency.http.get(f"/v1/scans/{scan_id}/report"), 409, "scan_not_finished")
    scanner.release.set()
    idle(app)
    assert agency.http.get(f"/v1/scans/{scan_id}/report").status_code == 200


def test_the_report_is_the_scanners_own_json_and_is_valid(app, a, report_validator):
    scan_id = a.scan(target="http://site-a.example/").json()["scan_id"]
    idle(app)
    response = a.http.get(f"/v1/scans/{scan_id}/report")
    assert response.status_code == 200 and response.headers["content-type"].startswith("application/json")
    report = response.json()
    report_validator.validate(report)
    assert report["schema_version"] == SCHEMA_VERSION and report["target"] == "http://site-a.example/"
    assert report["secrets_redacted"] is True and report["pages"][0]["url"] == "http://site-a.example/"
    stored = (app.state.settings.results_dir / app.state.repo.get_scan(a.id, scan_id)["result_path"]).read_bytes()
    assert response.content == stored  # what was written is what is served, byte for byte


def test_the_html_report_is_a_standalone_page_with_safe_headers(app, a):
    scan_id = a.scan(target="http://site-a.example/").json()["scan_id"]
    idle(app)
    response = a.http.get(f"/v1/scans/{scan_id}/report.html")
    assert response.status_code == 200 and response.headers["content-type"].startswith("text/html")
    assert "http://site-a.example/" in response.text and "<script" not in response.text
    assert (
        response.headers["content-security-policy"] == "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'"
    )
    assert response.headers["cache-control"] == "no-store" and response.headers["x-content-type-options"] == "nosniff"


def test_a_secret_in_the_target_is_masked_everywhere_it_is_shown_or_stored(app, a):
    leak = "SECRETVALUE123"
    target = f"http://site-a.example/?token={leak}"
    created = a.scan(target=target)
    scan_id = created.json()["scan_id"]
    idle(app)
    texts = [
        created.text,
        a.http.get(f"/v1/scans/{scan_id}").text,
        a.http.get("/v1/scans").text,
        a.http.get(f"/v1/scans/{scan_id}/report").text,
        a.http.get(f"/v1/scans/{scan_id}/report.html").text,
    ]
    assert not any(leak in text for text in texts)
    assert "token=<redacted len=" in a.http.get(f"/v1/scans/{scan_id}").json()["target"]
    folder = app.state.settings.results_dir
    assert not any(leak.encode() in path.read_bytes() for path in folder.rglob("*") if path.is_file())  # no stored file


def test_the_stored_report_is_unreadable_when_it_has_been_removed_and_says_so_without_a_path(app, a):
    scan_id = a.scan().json()["scan_id"]
    idle(app)
    (app.state.settings.results_dir / app.state.repo.get_scan(a.id, scan_id)["result_path"]).unlink()
    body = problem(a.http.get(f"/v1/scans/{scan_id}/report"), 500, "internal_error")
    assert "results" not in json.dumps(body) and scan_id not in json.dumps(body)


def test_results_are_filed_under_the_agency_and_the_client(app, a, b):
    mine, theirs = a.scan().json()["scan_id"], b.scan().json()["scan_id"]
    idle(app)
    base = app.state.settings.results_dir
    assert (base / a.id / a.client_id).is_dir() and (base / b.id / b.client_id).is_dir()
    files = sorted(str(p.relative_to(base)).replace("\\", "/") for p in base.rglob("*.json"))
    assert len(files) == 2 and all(f.startswith((a.id, b.id)) for f in files)
    assert any(f.endswith(f"{mine}.json") and f.startswith(a.id) for f in files)
    assert any(f.endswith(f"{theirs}.json") and f.startswith(b.id) for f in files)


@pytest.mark.parametrize(
    "junk", ["not-an-id", "scn_" + "u" * 26, "scn_" + "0" * 25, "cli_" + "0" * 26, "a" * 400, "%00"]
)
def test_a_scan_id_that_cannot_be_one_is_the_same_404(app, a, junk):
    reference = strip_id(problem(a.http.get(f"/v1/scans/{ids.new_id('scan')}"), 404, "not_found"))
    for path in ("", "/report", "/report.html"):
        assert strip_id(problem(a.http.get(f"/v1/scans/{junk}{path}"), 404, "not_found")) == reference


# --- finding scans again --------------------------------------------------------------------------


def test_scans_are_listed_newest_first_in_pages_without_gaps_or_repeats(app, a, clock):
    made = []
    for n in range(7):
        clock.advance(milliseconds=5)
        made.append(a.scan(target=f"http://site-{n}.example/").json()["scan_id"])
    idle(app)
    seen, cursor = [], None
    for _ in range(10):
        params = {"limit": 3, **({"cursor": cursor} if cursor else {})}
        page = a.http.get("/v1/scans", params=params).json()
        assert len(page["items"]) <= 3
        seen += [s["scan_id"] for s in page["items"]]
        cursor = page["next_cursor"]
        if cursor is None:
            break
    assert seen == sorted(made, reverse=True) and len(set(seen)) == 7


def test_the_last_page_has_no_cursor_even_when_it_is_exactly_full(app, a):
    for n in range(6):
        a.scan(target=f"http://site-{n}.example/")
    idle(app)
    first = a.http.get("/v1/scans", params={"limit": 3}).json()
    second = a.http.get("/v1/scans", params={"limit": 3, "cursor": first["next_cursor"]}).json()
    assert len(first["items"]) == len(second["items"]) == 3 and second["next_cursor"] is None


def test_scans_can_be_filtered_by_client_and_by_state(make_app, scanner):
    app = make_app({"max_concurrent_scans": 1, "max_concurrent_per_agency": 1})
    agency = Agency(app, "A")
    other = agency.http.post("/v1/clients", json={"display_name": "Second client"}).json()["client_id"]
    scanner.hold = True
    first = agency.scan(target="http://a.example/").json()["scan_id"]
    scanner.wait_started()
    second = agency.http.post(
        "/v1/scans", json={"client_id": other, "target": "http://b.example/", "attestation": ATTEST}
    ).json()["scan_id"]
    ids_of = lambda **q: [s["scan_id"] for s in agency.http.get("/v1/scans", params=q).json()["items"]]  # noqa: E731
    assert ids_of(client_id=other) == [second] and ids_of(client_id=agency.client_id) == [first]
    assert ids_of(status="running") == [first] and ids_of(status="queued") == [second]
    scanner.release.set()
    idle(app)
    assert sorted(ids_of(status="completed")) == sorted([first, second]) and ids_of(status="failed") == []


@pytest.mark.parametrize(
    "query",
    [{"status": "paused"}, {"client_id": "nope"}, {"client_id": "scn_" + "0" * 26}, {"limit": 0}, {"limit": 101}],
)
def test_a_bad_filter_is_a_422(a, query):
    problem(a.http.get("/v1/scans", params=query), 422, "validation_error")


@pytest.mark.parametrize("cursor", ["garbage", "!!!!", "a", "A" * 300])
def test_a_cursor_the_service_did_not_make_is_a_400(a, cursor):
    problem(a.http.get("/v1/scans", params={"cursor": cursor}), 400, "invalid_cursor")


def test_a_cursor_of_the_wrong_kind_is_a_400(a):
    import base64

    client_cursor = base64.urlsafe_b64encode(ids.new_id("client").encode()).decode().rstrip("=")
    problem(a.http.get("/v1/scans", params={"cursor": client_cursor}), 400, "invalid_cursor")


# --- what is written down -------------------------------------------------------------------------


def test_the_attestation_is_kept_with_the_scan_and_the_audit_log_has_no_target(app, a):
    scan_id = a.scan(target="http://site-a.example/path?token=SECRETVALUE5").json()["scan_id"]
    idle(app)
    row = app.state.repo.get_scan(a.id, scan_id)
    assert row["attestation"] == {
        "confirmed": True,
        "statement_version": "v1",
        "key_id": a.record["key_id"],
        "ip": row["attestation"]["ip"],
        "at": "2026-10-05T12:00:00.000Z",
        "target_host": "site-a.example",
    }
    assert row["attestation"]["ip"]
    entries = [e for e in app.state.repo.audit_entries(a.id) if e["action"] == "scan.create"]
    assert len(entries) == 1 and entries[0]["subject"] == scan_id and entries[0]["key_id"] == a.record["key_id"]
    assert entries[0]["detail"] == {"client_id": a.client_id, "statement_version": "v1", "crawl": False}
    assert "site-a" not in json.dumps(entries) and "SECRETVALUE5" not in json.dumps(entries)


def test_a_replayed_request_is_not_audited_twice(app, a):
    a.scan(key="k")
    a.scan(key="k")
    idle(app)
    assert len([e for e in app.state.repo.audit_entries(a.id) if e["action"] == "scan.create"]) == 1


def test_the_database_holds_no_report_content(app, a):
    scan_id = a.scan().json()["scan_id"]
    idle(app)
    with sqlite3.connect(app.state.settings.db_path) as raw:
        (summary,) = raw.execute("SELECT summary FROM scans WHERE scan_id = ?", (scan_id,)).fetchone()
    assert "findings" in json.loads(summary) and "evidence" not in summary and "description" not in summary


# --- the real scanner against a local site --------------------------------------------------------


SITE = {
    "/": Page(html("/a", "/b"), headers={"X-Frame-Options": "DENY"}, cookies=["sid=1; Path=/"]),
    "/a": Page(html()),
    "/b": Page(html()),
}


def test_a_real_scan_of_a_local_site_end_to_end(make_app, http_server, report_validator):
    handler = site_handler(SITE)
    base = http_server(handler)
    app = make_app({"scan_rate_limit": 1000.0}, fake=False)
    agency = Agency(app, "A")
    created = agency.scan(target=base, checks=["headers", "cookies", "exposed-files"])
    assert created.status_code == 202
    idle(app)
    scan = agency.http.get(f"/v1/scans/{created.json()['scan_id']}").json()
    assert (
        scan["status"] == "completed"
        and scan["summary"]["findings"] > 0
        and scan["summary"]["gate"]["incomplete"] is False
    )
    report = agency.http.get(f"/v1/scans/{scan['scan_id']}/report").json()
    report_validator.validate(report)
    assert (
        report["limits"]["rate_limit"] == app.state.settings.scan_rate_limit and report["limits"]["requests_sent"] > 5
    )
    assert {f["check"] for f in report["findings"]} >= {"security-headers", "cookies"}
    assert set(handler.methods) == {"GET"} and handler.hits[0] == "/"  # only GETs, as the scanner always sends
    assert "/a" not in handler.hits  # crawl was not asked for


def test_a_real_scan_with_crawl_visits_the_linked_pages(make_app, http_server, report_validator):
    handler = site_handler(SITE)
    base = http_server(handler)
    app = make_app({"crawl": CrawlOptions(max_pages=5), "scan_rate_limit": 1000.0}, fake=False)
    agency = Agency(app, "A")
    scan_id = agency.scan(target=base, checks=["headers", "cookies"], crawl=True).json()["scan_id"]
    idle(app)
    report = agency.http.get(f"/v1/scans/{scan_id}/report").json()
    report_validator.validate(report)
    assert report["crawl"]["pages_visited"] == 3 and len(report["pages"]) == 3 and "/a" in handler.hits
    summary = agency.http.get(f"/v1/scans/{scan_id}").json()["summary"]
    assert summary["pages_scanned"] == 3


def test_a_scan_of_a_site_that_is_down_completes_with_an_incomplete_report(make_app):
    app = make_app({"scan_timeout": 1}, fake=False)
    agency = Agency(app, "A")
    scan_id = agency.scan(target="http://127.0.0.1:1/").json()["scan_id"]  # nothing listens on port 1
    idle(app)
    scan = agency.http.get(f"/v1/scans/{scan_id}").json()
    assert (
        scan["status"] == "completed"
        and scan["summary"]["gate"]["incomplete"] is True
        and scan["summary"]["findings"] == 0
    )
    assert agency.http.get(f"/v1/scans/{scan_id}/report").json()["errors"]


def test_in_production_a_name_that_turns_internal_after_the_check_is_stopped_at_the_connection(
    make_app, http_server, monkeypatch
):
    """DNS rebinding: the submission check is fooled (here: bypassed), the connection check is not."""
    handler = site_handler(SITE)
    base = http_server(handler)  # a loopback address the scan would reach if nothing stopped it
    app = make_app({"allow_private_targets": False, "tls_probe": True, "scan_timeout": 2}, fake=False)
    agency = Agency(app, "A")
    monkeypatch.setattr(
        netguard, "check_target", lambda url, **kw: ["93.184.216.34"]
    )  # "it looked public a moment ago"
    scan_id = agency.scan(target=base).json()["scan_id"]
    idle(app)
    scan = agency.http.get(f"/v1/scans/{scan_id}").json()
    assert scan["status"] == "completed" and scan["summary"]["gate"]["incomplete"] is True
    assert handler.hits == []  # the scanner connected, was refused by the guard, and never sent a request
    report = agency.http.get(f"/v1/scans/{scan_id}/report").json()
    assert "may connect to" in json.dumps(report["errors"])  # the scanner says why, without naming an address


# --- the contract ---------------------------------------------------------------------------------


def test_the_scan_operations_are_in_the_contract_and_need_a_key():
    spec = openapi.build_spec()
    wanted = {
        ("post", "/v1/scans"): "createScan",
        ("get", "/v1/scans"): "listScans",
        ("get", "/v1/scans/{scan_id}"): "getScan",
        ("get", "/v1/scans/{scan_id}/report"): "getScanReport",
        ("get", "/v1/scans/{scan_id}/report.html"): "getScanReportHtml",
    }
    for (method, path), operation_id in wanted.items():
        operation = spec["paths"][path][method]
        assert operation["operationId"] == operation_id and operation["security"] and operation["tags"] == ["scans"]
    assert spec["info"]["version"] == "1.1.0"


def test_the_contract_documents_the_scan_request_and_its_headers():
    spec = openapi.build_spec()
    create = spec["paths"]["/v1/scans"]["post"]
    assert "202" in create["responses"] and set(create["responses"]["202"]["headers"]) == {
        "Location",
        "Idempotent-Replayed",
    }
    assert [p["name"] for p in create["parameters"]] == ["Idempotency-Key"]
    schema = spec["components"]["schemas"]["ScanCreate"]
    assert schema["additionalProperties"] is False and set(schema["required"]) == {"client_id", "target", "attestation"}
    assert spec["components"]["schemas"]["Attestation"]["additionalProperties"] is False
    assert sorted(spec["components"]["schemas"]["Scan"]["properties"]) == sorted(
        [
            "scan_id",
            "client_id",
            "target",
            "status",
            "checks",
            "crawl",
            "created_at",
            "started_at",
            "finished_at",
            "summary",
            "error",
            "report_available",
        ]
    )
    assert spec["components"]["schemas"]["Scan"]["properties"]["status"]["enum"] == [
        "queued",
        "running",
        "completed",
        "failed",
    ]


def test_the_report_endpoints_say_what_they_return():
    paths = openapi.build_spec()["paths"]
    assert list(paths["/v1/scans/{scan_id}/report"]["get"]["responses"]["200"]["content"]) == ["application/json"]
    assert list(paths["/v1/scans/{scan_id}/report.html"]["get"]["responses"]["200"]["content"]) == ["text/html"]
    for path in ("/v1/scans/{scan_id}/report", "/v1/scans/{scan_id}/report.html"):
        assert "409" in paths[path]["get"]["responses"]


def test_a_scan_response_never_has_more_fields_than_the_contract_names(app, a):
    scan_id = a.scan().json()["scan_id"]
    idle(app)
    fields = set(a.http.get(f"/v1/scans/{scan_id}").json())
    assert fields == set(openapi.build_spec()["components"]["schemas"]["Scan"]["properties"])
    assert "agency_id" not in fields and "result_path" not in fields and "target_host" not in fields


def test_waiting_scans_start_oldest_first(make_app, scanner):
    app = make_app({"max_concurrent_scans": 1, "max_concurrent_per_agency": 1})
    agency = Agency(app, "A")
    scanner.hold = True
    agency.scan(target="http://first.example/")
    scanner.wait_started()
    waiting = [agency.scan(target=f"http://wait-{n}.example/").json()["scan_id"] for n in range(3)]
    scanner.release.set()
    idle(app)
    started = [call["target"] for call in scanner.calls]
    assert started[0] == "http://first.example/"
    by_id = {s["scan_id"]: s["target"] for s in app.state.repo.list_scans(agency.id, limit=10)}
    assert started[1:] == [by_id[scan_id] for scan_id in sorted(waiting)]  # in the order they were asked for


def test_a_completed_scan_that_has_no_stored_result_is_a_fault_of_the_service_not_a_failed_scan(app, a):
    scan_id = a.scan().json()["scan_id"]
    idle(app)
    with sqlite3.connect(app.state.settings.db_path) as raw:
        raw.execute("UPDATE scans SET result_path = NULL WHERE scan_id = ?", (scan_id,))
    assert a.http.get(f"/v1/scans/{scan_id}").json()["report_available"] is False
    problem(a.http.get(f"/v1/scans/{scan_id}/report"), 500, "internal_error")  # not the 409 of a scan that failed
