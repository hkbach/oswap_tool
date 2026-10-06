"""The HTTP API of the agency service, version 1 (decision D12): authentication, clients, errors, limits, contract.

Everything runs in process against a throw-away database; no network and no real scan.
"""

from __future__ import annotations

import base64
import json
import logging
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
import yaml

pytest.importorskip("fastapi")
pytest.importorskip("httpx")

from fastapi.testclient import TestClient  # noqa: E402

from websec_scanner import __version__, catalog  # noqa: E402
from websec_scanner.models import SCHEMA_VERSION  # noqa: E402
from websec_scanner.service import api, ids, openapi  # noqa: E402
from websec_scanner.service.config import Settings  # noqa: E402
from websec_scanner.service.db import Repository  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
ALL = ["clients:read", "clients:write", "scans:read", "scans:write"]
PROBLEM = "application/problem+json"


class Clock:
    def __init__(self):
        self.now = datetime(2026, 10, 5, 12, 0, 0, tzinfo=UTC)

    def __call__(self):
        return self.now

    def advance(self, **kwargs):
        self.now += timedelta(**kwargs)


@pytest.fixture
def clock():
    return Clock()


@pytest.fixture
def settings(tmp_path):
    return Settings(data_dir=tmp_path / "data")


@pytest.fixture
def repo(settings, clock):
    repository = Repository(settings.db_path, clock=clock)
    repository.migrate()
    return repository


@pytest.fixture
def app(settings, repo):
    return api.create_app(settings, repo)


def connect(app, key=None):
    headers = {"Authorization": f"Bearer {key}"} if key else {}
    return TestClient(app, headers=headers, raise_server_exceptions=False)


class Agency:
    """An agency with a full-scope key, and a client that talks as it."""

    def __init__(self, app, repo, name):
        self.id = repo.create_agency(name)["agency_id"]
        self.record, self.key = repo.create_key(self.id, "backend", ALL)
        self.http = connect(app, self.key)


@pytest.fixture
def a(app, repo):
    return Agency(app, repo, "Agency A")


@pytest.fixture
def b(app, repo):
    return Agency(app, repo, "Agency B")


@pytest.fixture
def anon(app):
    return connect(app)


def without_id(body: dict) -> dict:
    return {k: v for k, v in body.items() if k != "request_id"}


def assert_problem(response, status, code):
    assert response.status_code == status, response.text
    assert response.headers["content-type"].startswith(PROBLEM)
    body = response.json()
    assert body["status"] == status and body["code"] == code
    assert body["type"] == f"urn:websec:problem:{code}"
    assert body["request_id"] == response.headers["x-request-id"] and body["request_id"].startswith("req_")
    assert isinstance(body["title"], str) and isinstance(body["detail"], str)
    return body


# --- health, the contract and what is not served --------------------------------------------------


def test_health_needs_no_key_and_says_nothing_about_the_data(anon):
    response = anon.get("/healthz")
    assert response.status_code == 200
    assert response.json() == {"status": "ok", "service_version": __version__}


def test_health_says_503_when_the_database_cannot_be_reached(anon, repo, monkeypatch):
    monkeypatch.setattr(repo, "ping", lambda: False)
    assert_problem(anon.get("/healthz"), 503, "unavailable")


def test_the_contract_is_public_and_is_the_one_the_code_generates(anon, app):
    response = anon.get("/v1/openapi.json")
    assert response.status_code == 200 and response.json() == app.openapi()


def test_there_is_no_interactive_page_that_would_load_third_party_scripts(anon):
    for path in ("/docs", "/redoc", "/docs/oauth2-redirect"):
        assert_problem(anon.get(path), 404, "not_found")


def test_an_unknown_route_and_a_wrong_method_are_problems_too(anon, a):
    assert_problem(anon.get("/v1/nothing"), 404, "not_found")
    assert_problem(a.http.put("/v1/clients"), 405, "method_not_allowed")


def test_no_cross_origin_access_is_granted(anon):
    response = anon.options(
        "/v1/clients", headers={"Origin": "https://agency.example", "Access-Control-Request-Method": "GET"}
    )
    assert_problem(response, 405, "method_not_allowed")
    assert not any(name.lower().startswith("access-control-") for name in response.headers)
    assert "access-control-allow-origin" not in anon.get("/healthz", headers={"Origin": "https://x.example"}).headers


# --- authentication -------------------------------------------------------------------------------


def test_a_call_without_a_key_is_refused_with_a_challenge(anon):
    response = anon.get("/v1/clients")
    assert_problem(response, 401, "unauthorized")
    assert response.headers["www-authenticate"] == "Bearer"


GOOD_SHAPE = "wsk_abcdefgh_" + "A" * 43


@pytest.mark.parametrize(
    "authorization",
    [
        "Basic dXNlcjpwYXNz",
        "Bearer",
        "Bearer ",
        "Bearer not-a-key",
        "Bearer wsk_",
        f"Bearer {GOOD_SHAPE}",  # well-formed, but nobody has it
        f"Bearer {GOOD_SHAPE} ",
        f"Bearer  {GOOD_SHAPE}",
        f"bearer {GOOD_SHAPE}",
        "Token " + GOOD_SHAPE,
        GOOD_SHAPE,
    ],
)
def test_anything_that_is_not_a_working_key_is_refused(anon, authorization):
    assert_problem(anon.get("/v1/clients", headers={"Authorization": authorization}), 401, "unauthorized")


def test_every_reason_for_refusing_a_key_looks_the_same(app, repo, a, anon, clock):
    """A caller must not learn whether a handle exists, whether the secret was wrong, or why a key stopped."""
    handle, secret = a.key.split("_")[1], a.key.split("_", 2)[2]
    refusals = {}
    refusals["no key"] = anon.get("/v1/clients")
    refusals["malformed"] = connect(app, "nonsense").get("/v1/clients")
    refusals["unknown handle"] = connect(app, f"wsk_zzzzzzzz_{secret}").get("/v1/clients")
    refusals["wrong secret"] = connect(app, f"wsk_{handle}_{'B' * 43}").get("/v1/clients")
    expired_record, expired_key = repo.create_key(a.id, "short", ALL, expires_in_days=1)
    revoked_record, revoked_key = repo.create_key(a.id, "old", ALL)
    repo.revoke_key(revoked_record["key_id"])
    refusals["revoked"] = connect(app, revoked_key).get("/v1/clients")
    clock.advance(days=2)
    refusals["expired"] = connect(app, expired_key).get("/v1/clients")
    repo.set_agency_status(a.id, "suspended")
    refusals["suspended agency"] = connect(app, a.key).get("/v1/clients")
    bodies = {name: without_id(assert_problem(r, 401, "unauthorized")) for name, r in refusals.items()}
    assert len({json.dumps(b, sort_keys=True) for b in bodies.values()}) == 1, bodies
    assert len({r.headers["www-authenticate"] for r in refusals.values()}) == 1


def test_a_suspended_agency_works_again_when_it_is_activated(app, repo, a):
    repo.set_agency_status(a.id, "suspended")
    assert a.http.get("/v1/clients").status_code == 401
    repo.set_agency_status(a.id, "active")
    assert a.http.get("/v1/clients").status_code == 200


def test_a_key_that_has_not_expired_yet_works_until_its_last_moment(app, repo, a, clock):
    _, key = repo.create_key(a.id, "k", ALL, expires_in_days=1)
    clock.advance(hours=23, minutes=59)
    assert connect(app, key).get("/v1/clients").status_code == 200
    clock.advance(minutes=2)
    assert connect(app, key).get("/v1/clients").status_code == 401


def test_a_working_key_notes_when_it_was_used(a, repo):
    assert repo.find_key(a.record["handle"])["last_used_at"] is None
    a.http.get("/v1/clients")
    assert repo.find_key(a.record["handle"])["last_used_at"] == "2026-10-05T12:00:00.000Z"


def test_a_refused_call_does_not_count_as_a_use(app, repo, a):
    connect(app, f"wsk_{a.record['handle']}_{'B' * 43}").get("/v1/clients")
    assert repo.find_key(a.record["handle"])["last_used_at"] is None


def test_the_key_itself_is_never_in_an_answer_or_a_log_line(app, repo, a, caplog):
    caplog.set_level(logging.DEBUG)
    secret = a.key.split("_", 2)[2]
    texts = [a.http.get("/v1/clients").text, a.http.post("/v1/clients", json={"display_name": "x"}).text,
             connect(app, a.key + "x").get("/v1/clients").text]  # fmt: skip
    assert not any(secret in text or a.key in text for text in texts)
    assert secret not in caplog.text


# --- scopes ---------------------------------------------------------------------------------------


def key_with(app, repo, agency_id, scopes):
    return connect(app, repo.create_key(agency_id, "limited", scopes)[1])


def test_a_read_only_key_can_read_but_not_write(app, repo, a):
    reader = key_with(app, repo, a.id, ["clients:read"])
    client_id = a.http.post("/v1/clients", json={"display_name": "Acme"}).json()["client_id"]
    assert reader.get(f"/v1/clients/{client_id}").status_code == 200
    assert reader.get("/v1/clients").status_code == 200
    for response in (
        reader.post("/v1/clients", json={"display_name": "x"}),
        reader.patch(f"/v1/clients/{client_id}", json={"display_name": "x"}),
        reader.delete(f"/v1/clients/{client_id}"),
    ):
        body = assert_problem(response, 403, "forbidden")
        assert "clients:write" in body["detail"]
    assert a.http.get(f"/v1/clients/{client_id}").json()["display_name"] == "Acme"  # nothing changed


def test_a_write_only_key_cannot_read(app, repo, a):
    writer = key_with(app, repo, a.id, ["clients:write"])
    assert writer.post("/v1/clients", json={"display_name": "x"}).status_code == 201
    assert_problem(writer.get("/v1/clients"), 403, "forbidden")


def test_a_key_without_scopes_can_only_ask_what_a_request_may_contain(app, repo, a):
    bare = key_with(app, repo, a.id, [])
    assert bare.get("/v1/options").status_code == 200
    assert_problem(bare.get("/v1/clients"), 403, "forbidden")


# --- options --------------------------------------------------------------------------------------


def test_options_need_a_key(anon):
    assert_problem(anon.get("/v1/options"), 401, "unauthorized")


def test_options_describe_what_a_scan_request_can_ask_for(a, settings):
    data = a.http.get("/v1/options").json()
    assert data["api_version"] == "v1" and data["scanner_version"] == __version__
    assert data["report_schema_version"] == SCHEMA_VERSION
    assert data["check_groups"] == [
        {"id": g.id, "title": g.title, "description": g.description} for g in catalog.CHECK_GROUPS
    ]
    assert data["crawl"] == {"max_depth": 2, "max_pages": 50, "max_duration": 60.0, "respect_robots": True}


def test_options_show_the_operators_crawl_limits(tmp_path):
    from websec_scanner.crawler.crawl import CrawlOptions

    settings = Settings(data_dir=tmp_path / "d", crawl=CrawlOptions(max_depth=1, max_pages=9, max_duration=5))
    app = api.create_app(settings)
    repository = app.state.repo
    key = repository.create_key(repository.create_agency("A")["agency_id"], "k", [])[1]
    assert connect(app, key).get("/v1/options").json()["crawl"] == {
        "max_depth": 1,
        "max_pages": 9,
        "max_duration": 5.0,
        "respect_robots": True,
    }


# --- clients --------------------------------------------------------------------------------------


def test_a_client_is_created_read_listed_changed_and_deleted(a):
    created = a.http.post(
        "/v1/clients",
        json={"display_name": "Acme Ltd", "external_ref": "acme-1", "metadata": {"plan": "gold", "seats": 3}},
    )
    assert created.status_code == 201
    client = created.json()
    assert ids.is_valid("client", client["client_id"])
    assert client["external_ref"] == "acme-1" and client["metadata"] == {"plan": "gold", "seats": 3}
    assert client["created_at"] == client["updated_at"] == "2026-10-05T12:00:00.000Z"
    assert a.http.get(f"/v1/clients/{client['client_id']}").json() == client
    assert a.http.get("/v1/clients").json() == {"items": [client], "next_cursor": None}
    patched = a.http.patch(f"/v1/clients/{client['client_id']}", json={"display_name": "Acme Limited"})
    assert patched.status_code == 200 and patched.json()["display_name"] == "Acme Limited"
    assert patched.json()["external_ref"] == "acme-1" and patched.json()["metadata"] == client["metadata"]
    assert a.http.delete(f"/v1/clients/{client['client_id']}").status_code == 204
    assert_problem(a.http.get(f"/v1/clients/{client['client_id']}"), 404, "not_found")
    assert a.http.get("/v1/clients").json()["items"] == []


def test_a_delete_answers_204_with_nothing_in_the_body(a):
    client_id = a.http.post("/v1/clients", json={"display_name": "x"}).json()["client_id"]
    response = a.http.delete(f"/v1/clients/{client_id}")
    assert response.status_code == 204 and response.content == b""


def test_labels_can_be_replaced_and_cleared(a):
    client_id = a.http.post("/v1/clients", json={"display_name": "x", "metadata": {"a": "1"}}).json()["client_id"]
    assert a.http.patch(f"/v1/clients/{client_id}", json={"metadata": {"b": 2}}).json()["metadata"] == {"b": 2}
    assert a.http.patch(f"/v1/clients/{client_id}", json={"metadata": {}}).json()["metadata"] == {}


def test_the_same_external_ref_twice_is_a_conflict_until_the_first_is_deleted(a):
    first = a.http.post("/v1/clients", json={"display_name": "One", "external_ref": "r"}).json()
    assert_problem(
        a.http.post("/v1/clients", json={"display_name": "Two", "external_ref": "r"}), 409, "external_ref_taken"
    )
    a.http.delete(f"/v1/clients/{first['client_id']}")
    assert a.http.post("/v1/clients", json={"display_name": "Two", "external_ref": "r"}).status_code == 201


def test_two_agencies_may_use_the_same_external_ref(a, b):
    assert a.http.post("/v1/clients", json={"display_name": "A's", "external_ref": "same"}).status_code == 201
    assert b.http.post("/v1/clients", json={"display_name": "B's", "external_ref": "same"}).status_code == 201


def test_an_agency_cannot_reach_another_agencys_client_in_any_way(a, b):
    mine = a.http.post("/v1/clients", json={"display_name": "Mine", "external_ref": "m"}).json()
    path = f"/v1/clients/{mine['client_id']}"
    unknown = f"/v1/clients/{ids.new_id('client')}"
    for method, body in (("get", None), ("patch", {"display_name": "taken"}), ("delete", None)):
        theirs = getattr(b.http, method)(path, **({"json": body} if body else {}))
        nothing = getattr(b.http, method)(unknown, **({"json": body} if body else {}))
        # the answer for someone else's client is word for word the answer for a client that does not exist
        assert without_id(assert_problem(theirs, 404, "not_found")) == without_id(
            assert_problem(nothing, 404, "not_found")
        )
    assert b.http.get("/v1/clients").json() == {"items": [], "next_cursor": None}
    assert b.http.get("/v1/clients", params={"external_ref": "m"}).json()["items"] == []
    assert a.http.get(path).json()["display_name"] == "Mine"  # untouched by the attempts


def test_an_id_that_cannot_be_a_client_is_the_same_404(a):
    reference = without_id(assert_problem(a.http.get(f"/v1/clients/{ids.new_id('client')}"), 404, "not_found"))
    for bad in ("not-an-id", ids.new_id("agency"), "cli_" + "u" * 26, "cli_" + "0" * 25, "%00", "a" * 500):
        assert without_id(assert_problem(a.http.get(f"/v1/clients/{bad}"), 404, "not_found")) == reference, bad
    for traversal in ("..%2F..%2Fetc", "..", "%2e%2e"):  # these do not even reach the route: a 404 all the same
        assert_problem(a.http.get(f"/v1/clients/{traversal}"), 404, "not_found")


@pytest.mark.parametrize(
    ("body", "where"),
    [
        ({}, "display_name"),
        ({"display_name": ""}, "display_name"),
        ({"display_name": "   "}, "display_name"),
        ({"display_name": "x" * 201}, "display_name"),
        ({"display_name": 5}, "display_name"),
        ({"display_name": "x", "external_ref": ""}, "external_ref"),
        ({"display_name": "x", "external_ref": "has space"}, "external_ref"),
        ({"display_name": "x", "external_ref": "a/b"}, "external_ref"),
        ({"display_name": "x", "external_ref": "é"}, "external_ref"),
        ({"display_name": "x", "external_ref": "r" * 129}, "external_ref"),
        ({"display_name": "x", "metadata": "text"}, "metadata"),
        ({"display_name": "x", "metadata": {"a": {"nested": 1}}}, "metadata"),
        ({"display_name": "x", "metadata": {"a": [1]}}, "metadata"),
        ({"display_name": "x", "metadata": {"k" * 65: "v"}}, "metadata"),
        ({"display_name": "x", "metadata": {"bad key": "v"}}, "metadata"),
        ({"display_name": "x", "metadata": {"a": "v" * 257}}, "metadata"),
        ({"display_name": "x", "metadata": {f"k{n}": n for n in range(21)}}, "metadata"),
        ({"display_name": "x", "metadata": {"api_token": "v"}}, "metadata"),
        ({"display_name": "x", "metadata": {"Password": "v"}}, "metadata"),
        ({"display_name": "x", "metadata": {"client-secret": "v"}}, "metadata"),
        ({"display_name": "x", "status": "deleted"}, "status"),
        ({"display_name": "x", "agency_id": "ag_other"}, "agency_id"),
        ({"display_name": "x", "client_id": "cli_x"}, "client_id"),
        ({"display_name": "x", "password": "p"}, "password"),
    ],
)
def test_an_invalid_new_client_is_a_422_that_says_where(a, body, where):
    response = a.http.post("/v1/clients", json=body)
    problem = assert_problem(response, 422, "validation_error")
    assert any(where in [str(part) for part in error["loc"]] for error in problem["errors"]), problem
    assert a.http.get("/v1/clients").json()["items"] == []  # nothing was made


def test_a_422_never_echoes_what_was_sent(a):
    sentinel = "SENTINEL-PASSWORD-VALUE-123"
    for body in (
        {"display_name": "x", "password": sentinel},
        {"display_name": sentinel * 20},
        {"display_name": "x", "metadata": {sentinel: "v" * 300}},
        {"display_name": "x", "external_ref": sentinel + " bad"},
    ):
        response = a.http.post("/v1/clients", json=body)
        assert response.status_code == 422 and sentinel not in response.text, response.text
    broken = a.http.post(
        "/v1/clients", content='{"display_name": "' + sentinel, headers={"Content-Type": "application/json"}
    )
    assert broken.status_code == 422 and sentinel not in broken.text


def test_a_body_that_is_not_json_is_a_422(a):
    for content in ("", "[]", "null", "not json", '"text"'):
        response = a.http.post("/v1/clients", content=content, headers={"Content-Type": "application/json"})
        assert_problem(response, 422, "validation_error")


def test_an_update_has_to_change_something(a):
    client_id = a.http.post("/v1/clients", json={"display_name": "x"}).json()["client_id"]
    for body in ({}, {"display_name": None}, {"metadata": None}):
        assert_problem(a.http.patch(f"/v1/clients/{client_id}", json=body), 422, "validation_error")
    assert_problem(a.http.patch(f"/v1/clients/{client_id}", json={"external_ref": "new"}), 422, "validation_error")


def test_an_update_checks_labels_as_strictly_as_a_create(a):
    client_id = a.http.post("/v1/clients", json={"display_name": "x"}).json()["client_id"]
    assert_problem(a.http.patch(f"/v1/clients/{client_id}", json={"metadata": {"token": "v"}}), 422, "validation_error")
    assert_problem(a.http.patch(f"/v1/clients/{client_id}", json={"display_name": " "}), 422, "validation_error")


def test_text_is_stored_without_the_space_around_it(a):
    client = a.http.post("/v1/clients", json={"display_name": "  Acme  ", "external_ref": " r1 "}).json()
    assert client["display_name"] == "Acme" and client["external_ref"] == "r1"


def test_markup_in_a_name_is_kept_as_text_and_comes_back_as_json(a):
    name = '<script>alert(1)</script> & "quotes" é中'
    response = a.http.post("/v1/clients", json={"display_name": name})
    assert response.headers["content-type"].startswith("application/json")
    assert response.json()["display_name"] == name


# --- listing --------------------------------------------------------------------------------------


def make_clients(a, count):
    return [
        a.http.post("/v1/clients", json={"display_name": f"c{n}", "external_ref": f"r{n}"}).json()["client_id"]
        for n in range(count)
    ]


def test_pages_follow_one_another_without_gaps_or_repeats(a):
    made = make_clients(a, 7)
    seen, cursor = [], None
    for _ in range(10):
        params = {"limit": 3, **({"cursor": cursor} if cursor else {})}
        page = a.http.get("/v1/clients", params=params).json()
        assert len(page["items"]) <= 3
        seen += [c["client_id"] for c in page["items"]]
        cursor = page["next_cursor"]
        if cursor is None:
            break
    assert seen == sorted(made) and len(set(seen)) == 7


def test_the_last_page_has_no_cursor_even_when_it_is_exactly_full(a):
    make_clients(a, 6)
    first = a.http.get("/v1/clients", params={"limit": 3}).json()
    second = a.http.get("/v1/clients", params={"limit": 3, "cursor": first["next_cursor"]}).json()
    assert len(first["items"]) == len(second["items"]) == 3 and second["next_cursor"] is None


def test_an_empty_list_is_an_empty_page(a):
    assert a.http.get("/v1/clients").json() == {"items": [], "next_cursor": None}


def test_the_default_page_is_50_and_the_biggest_is_100(a, settings):
    assert settings.default_page_size == 50 and settings.max_page_size == 100
    for limit in (1, 100):
        assert a.http.get("/v1/clients", params={"limit": limit}).status_code == 200
    for limit in (0, -1, 101, "x", ""):
        assert_problem(a.http.get("/v1/clients", params={"limit": limit}), 422, "validation_error")


def test_a_client_can_be_found_by_its_external_ref(a):
    made = make_clients(a, 4)
    assert [c["client_id"] for c in a.http.get("/v1/clients", params={"external_ref": "r2"}).json()["items"]] == [
        made[2]
    ]
    assert a.http.get("/v1/clients", params={"external_ref": "missing"}).json()["items"] == []
    assert_problem(a.http.get("/v1/clients", params={"external_ref": "bad ref"}), 422, "validation_error")


def test_a_deleted_client_leaves_the_list_and_the_paging_stays_consistent(a):
    made = make_clients(a, 5)
    a.http.delete(f"/v1/clients/{made[1]}")
    listed = [c["client_id"] for c in a.http.get("/v1/clients").json()["items"]]
    assert listed == [m for m in sorted(made) if m != made[1]]


def cursor_of(client_id: str) -> str:
    return base64.urlsafe_b64encode(client_id.encode()).decode().rstrip("=")


@pytest.mark.parametrize(
    "cursor",
    ["garbage", "!!!!", "", "a", cursor_of("not-an-id"), cursor_of(ids.new_id("agency")),
     cursor_of("cli_" + "u" * 26), "%00", cursor_of("cli_" + "0" * 26)[:-3], "A" * 500],
)  # fmt: skip
def test_a_cursor_that_the_service_did_not_make_is_a_400(a, cursor):
    response = a.http.get("/v1/clients", params={"cursor": cursor})
    if cursor == "":
        assert response.status_code == 200  # an empty cursor is no cursor
    else:
        assert_problem(response, 400, "invalid_cursor")


def test_a_cursor_of_another_agencys_client_is_only_a_position(a, b):
    theirs = make_clients(b, 1)[0]
    mine = make_clients(a, 3)
    page = a.http.get("/v1/clients", params={"cursor": cursor_of(theirs)}).json()
    assert [c["client_id"] for c in page["items"]] == [m for m in sorted(mine) if m > theirs]  # no error, no leak


# --- what is written down -------------------------------------------------------------------------


def test_every_change_is_in_the_audit_log_with_who_and_from_where(a, repo):
    client_id = a.http.post("/v1/clients", json={"display_name": "Secret Client Name"}).json()["client_id"]
    a.http.patch(f"/v1/clients/{client_id}", json={"display_name": "Other Secret Name"})
    a.http.delete(f"/v1/clients/{client_id}")
    a.http.get(f"/v1/clients/{client_id}")
    entries = [e for e in repo.audit_entries(a.id) if e["action"].startswith("client.")]
    assert [e["action"] for e in entries] == ["client.create", "client.update", "client.delete"]
    assert {e["key_id"] for e in entries} == {a.record["key_id"]} and {e["subject"] for e in entries} == {client_id}
    assert all(e["ip"] for e in entries)
    assert "Secret" not in json.dumps(entries)  # what clients are called is not in the log


# --- errors and limits ----------------------------------------------------------------------------


def test_an_unexpected_failure_is_a_500_that_gives_nothing_away_and_is_logged_with_the_request_id(
    a, repo, monkeypatch, caplog
):
    def boom(*_args, **_kwargs):
        raise RuntimeError("database password is hunter2")

    monkeypatch.setattr(repo, "list_clients", boom)
    caplog.set_level(logging.ERROR, logger="websec_scanner.service")
    response = a.http.get("/v1/clients")
    body = assert_problem(response, 500, "internal_error")
    assert "hunter2" not in response.text and "RuntimeError" not in response.text
    assert body["request_id"] in caplog.text and "RuntimeError" in caplog.text  # the operator can find it


def test_a_body_over_the_limit_is_refused_before_it_is_read(a, settings):
    big = json.dumps({"display_name": "x", "metadata": {"a": "v" * (settings.max_body_bytes)}})
    assert len(big) > settings.max_body_bytes
    response = a.http.post("/v1/clients", content=big, headers={"Content-Type": "application/json"})
    body = assert_problem(response, 413, "body_too_large")
    assert str(settings.max_body_bytes) in body["detail"]


def test_a_body_just_under_the_limit_is_read(a, settings):
    padding = settings.max_body_bytes - len(json.dumps({"display_name": "x", "metadata": {}})) - 40
    content = json.dumps({"display_name": "x", "metadata": {"a": "v"}, "pad": "p" * padding})
    assert len(content) < settings.max_body_bytes
    response = a.http.post("/v1/clients", content=content, headers={"Content-Type": "application/json"})
    assert_problem(response, 422, "validation_error")  # read, understood, and refused for the unknown field


def test_a_body_sent_in_chunks_is_limited_too(a, settings):
    def chunks():
        for _ in range(settings.max_body_bytes // 1024 + 10):
            yield b"x" * 1024

    response = a.http.post("/v1/clients", content=chunks(), headers={"Content-Type": "application/json"})
    assert_problem(response, 413, "body_too_large")


def test_a_refusal_of_size_comes_before_a_refusal_of_the_key(anon, settings):
    response = anon.post(
        "/v1/clients", content=b"x" * (settings.max_body_bytes + 1), headers={"Content-Type": "application/json"}
    )
    assert response.status_code == 413  # nothing is read for a caller who is not even known


def test_every_answer_carries_a_fresh_request_id_and_safe_headers(a, anon):
    seen = set()
    for response in (a.http.get("/v1/clients"), anon.get("/v1/clients"), anon.get("/healthz"), anon.get("/nope")):
        seen.add(response.headers["x-request-id"])
        assert response.headers["cache-control"] == "no-store"
        assert response.headers["x-content-type-options"] == "nosniff"
    assert len(seen) == 4


def test_a_request_id_sent_by_the_caller_is_ignored(anon):
    for sent in ("req_forged", "req_0000000000000000", "a" * 200, "<script>"):
        response = anon.get("/healthz", headers={"X-Request-Id": sent})
        assert response.headers["x-request-id"] != sent and response.headers["x-request-id"].startswith("req_")
    problem = anon.get("/v1/clients", headers={"X-Request-Id": "req_forged"})
    assert problem.json()["request_id"] != "req_forged"  # nor in the body of an error


# --- the contract file ----------------------------------------------------------------------------


def shape(spec: dict) -> dict:
    """What agencies depend on, so that a different FastAPI version's spelling of the same thing does not matter."""
    operations = {}
    for path, methods in spec["paths"].items():
        for method, operation in methods.items():
            operations[f"{method.upper()} {path}"] = {
                "operationId": operation["operationId"],
                "tags": operation.get("tags"),
                "parameters": sorted(
                    (p["name"], p["in"], p.get("required", False)) for p in operation.get("parameters", [])
                ),
                "body": operation.get("requestBody", {}).get("content", {}).get("application/json", {}).get("schema"),
                "responses": {s: sorted(r.get("content", {})) for s, r in operation["responses"].items()},
                "secured": bool(operation.get("security")),
            }
    schemas = {
        name: (
            sorted(schema.get("required", [])),
            sorted(schema.get("properties", {})),
            schema.get("additionalProperties"),
        )
        for name, schema in spec["components"]["schemas"].items()
    }
    return {
        "openapi": spec["openapi"][:3],
        "version": spec["info"]["version"],
        "operations": operations,
        "schemas": schemas,
        "security": spec["components"]["securitySchemes"],
    }


def test_the_committed_contract_is_what_the_code_says():
    committed = yaml.safe_load((ROOT / "docs" / "openapi.yaml").read_text(encoding="utf-8"))
    assert shape(committed) == shape(openapi.build_spec()), (
        "regenerate: python -m websec_scanner.service.openapi --write docs/openapi.yaml"
    )


def test_every_operation_but_the_health_check_asks_for_a_key():
    spec = openapi.build_spec()
    for path, methods in spec["paths"].items():
        for method, operation in methods.items():
            assert bool(operation.get("security")) == (path != "/healthz"), f"{method} {path}"


def test_operation_ids_are_unique_and_every_error_is_a_problem():
    spec = openapi.build_spec()
    operation_ids = [op["operationId"] for methods in spec["paths"].values() for op in methods.values()]
    assert len(operation_ids) == len(set(operation_ids)) == 7
    for methods in spec["paths"].values():
        for operation in methods.values():
            for status, response in operation["responses"].items():
                if status[0] in "45":
                    assert list(response["content"]) == [PROBLEM], (operation["operationId"], status)
                    assert response["content"][PROBLEM]["schema"] == {"$ref": "#/components/schemas/Problem"}


def test_the_contract_has_no_leftover_default_error_shapes():
    schemas = openapi.build_spec()["components"]["schemas"]
    assert "HTTPValidationError" not in schemas and "ValidationError" not in schemas and "Problem" in schemas


def test_request_bodies_forbid_unknown_fields_in_the_contract():
    schemas = openapi.build_spec()["components"]["schemas"]
    assert (
        schemas["ClientCreate"]["additionalProperties"] is False
        and schemas["ClientUpdate"]["additionalProperties"] is False
    )


def test_a_key_is_expired_from_the_very_moment_it_says(app, repo, a, clock):
    _, key = repo.create_key(a.id, "k", ALL, expires_in_days=1)
    clock.advance(days=1)  # exactly the moment in expires_at
    assert connect(app, key).get("/v1/clients").status_code == 401


def test_the_secret_is_compared_in_constant_time(app, a, monkeypatch):
    import hmac

    calls = []
    real = hmac.compare_digest
    monkeypatch.setattr(hmac, "compare_digest", lambda x, y: calls.append(1) or real(x, y))
    assert a.http.get("/v1/clients").status_code == 200
    assert connect(app, f"wsk_zzzzzzzz_{'B' * 43}").get("/v1/clients").status_code == 401  # an unknown key too
    assert len(calls) == 2


def test_junk_ids_never_reach_the_database(a, repo, monkeypatch):
    calls = []
    monkeypatch.setattr(repo, "get_client", lambda *args, **kwargs: calls.append(args))
    monkeypatch.setattr(repo, "update_client", lambda *args, **kwargs: calls.append(args))
    monkeypatch.setattr(repo, "delete_client", lambda *args, **kwargs: calls.append(args))
    for junk in ("not-an-id", "cli_" + "u" * 26, "a" * 500):
        a.http.get(f"/v1/clients/{junk}")
        a.http.patch(f"/v1/clients/{junk}", json={"display_name": "x"})
        a.http.delete(f"/v1/clients/{junk}")
    assert calls == []


def test_a_body_of_exactly_the_limit_is_read_and_one_byte_more_is_not(a, settings):
    exact = b" " * settings.max_body_bytes
    over = b" " * (settings.max_body_bytes + 1)
    headers = {"Content-Type": "application/json"}
    assert_problem(
        a.http.post("/v1/clients", content=exact, headers=headers), 422, "validation_error"
    )  # read (and empty)
    assert_problem(a.http.post("/v1/clients", content=over, headers=headers), 413, "body_too_large")


def test_every_documented_422_says_what_it_means():
    spec = openapi.build_spec()
    texts = {
        response["description"]
        for methods in spec["paths"].values()
        for operation in methods.values()
        for status, response in operation["responses"].items()
        if status == "422"
    }
    assert texts == {"The request is not valid; `errors` says where."}


def test_a_declared_size_over_the_limit_is_refused_without_reading_the_body(settings):
    import asyncio

    from websec_scanner.service.middleware import BodyLimit

    reads, sent = [], []

    async def inner(scope, receive, send):  # pragma: no cover - must not be reached
        raise AssertionError("the application was called")

    async def receive():
        reads.append(1)
        return {"type": "http.request", "body": b"x", "more_body": False}

    async def send(message):
        sent.append(message)

    scope = {
        "type": "http",
        "method": "POST",
        "path": "/v1/clients",
        "headers": [(b"content-length", str(settings.max_body_bytes + 1).encode())],
        "state": {"request_id": "req_test"},
    }
    asyncio.run(BodyLimit(inner, settings.max_body_bytes)(scope, receive, send))
    assert reads == [] and sent[0]["status"] == 413
