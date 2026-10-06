"""The base of the agency API (decision D12): ids, API keys, the database and the settings.

Nothing here needs FastAPI: these modules use the standard library only, and the admin tool runs without it.
"""

from __future__ import annotations

import re
import sqlite3
from datetime import UTC, datetime, timedelta, timezone

import pytest

from websec_scanner.service import config, db, ids, security

# --- ids ---------------------------------------------------------------------------------------------------


@pytest.mark.parametrize(("kind", "prefix"), [("agency", "ag"), ("client", "cli"), ("scan", "scn"), ("key", "key")])
def test_an_id_has_its_kind_in_front_and_26_characters_after(kind, prefix):
    value = ids.new_id(kind)
    assert re.fullmatch(rf"{prefix}_[0-9a-hjkmnp-tv-z]{{26}}", value)
    assert ids.is_valid(kind, value)


def test_an_id_is_only_valid_for_its_own_kind():
    value = ids.new_id("client")
    assert not any(ids.is_valid(kind, value) for kind in ("agency", "scan", "key"))


@pytest.mark.parametrize(
    "bad",
    [None, 5, b"cli_" + b"0" * 26, "", "cli_", "cli_" + "0" * 25, "cli_" + "0" * 27, "cli_" + "I" * 26,
     "cli_" + "i" * 26, "cli_" + "u" * 26, "CLI_" + "0" * 26, " cli_" + "0" * 26,
     "cli_" + "0" * 26 + "\\n", "cli_" + "0" * 25 + "/", "../" + "0" * 26],
)  # fmt: skip
def test_things_that_are_not_ids_are_refused(bad):
    assert not ids.is_valid("client", bad)


def test_ids_sort_by_creation_time():
    earlier, later = ids.new_id("client", now_ms=1_000_000), ids.new_id("client", now_ms=1_000_001)
    assert earlier < later
    assert ids.created_ms(earlier) == 1_000_000 and ids.created_ms(later) == 1_000_001


def test_ids_made_in_the_same_millisecond_are_still_different():
    assert len({ids.new_id("scan", now_ms=5) for _ in range(500)}) == 500


def test_the_time_in_an_id_is_now():
    import time

    before = int(time.time() * 1000)
    value = ids.new_id("client")
    assert before <= ids.created_ms(value) <= int(time.time() * 1000)


# --- API keys ------------------------------------------------------------------------------------------------


def test_a_key_has_a_handle_and_a_secret():
    new = security.generate_key()
    assert re.fullmatch(r"wsk_[a-z0-9]{8}_[A-Za-z0-9_-]{43}", new.full)
    handle, secret = security.split_key(new.full)
    assert handle == new.handle and security.is_handle(handle)
    assert security.verify_secret(secret, new.secret_hash)


def test_only_a_hash_of_the_secret_is_kept():
    new = security.generate_key()
    _, secret = security.split_key(new.full)
    assert secret not in new.secret_hash and new.secret_hash != secret
    assert re.fullmatch(r"[0-9a-f]{64}", new.secret_hash)


def test_keys_are_not_guessable_from_each_other():
    keys = [security.generate_key() for _ in range(200)]
    assert len({k.full for k in keys}) == len({k.handle for k in keys}) == 200


@pytest.mark.parametrize(
    "token",
    ["", "wsk", "wsk_", "wsk_abcdefgh", "wsk_abcdefgh_", "wsk_abcdefgh_" + "A" * 42, "wsk_abcdefgh_" + "A" * 44,
     "wsk_ABCDEFGH_" + "A" * 43, "wsk_abcdefg_" + "A" * 43, "xxx_abcdefgh_" + "A" * 43, " wsk_abcdefgh_" + "A" * 43,
     "wsk_abcdefgh_" + "A" * 43 + " ", "wsk_abcdefgh_" + "A" * 42 + "!", "wsk_abcdefgh_" + "A" * 42 + "\\n"],
)  # fmt: skip
def test_a_malformed_key_is_not_split(token):
    assert security.split_key(token) is None


def test_a_wrong_secret_does_not_verify():
    new = security.generate_key()
    assert not security.verify_secret("x" * 43, new.secret_hash)
    assert not security.verify_secret("", new.secret_hash)


def test_an_unknown_key_never_verifies_even_with_the_decoy_secret():
    assert security.verify_secret("anything", None) is False
    assert security.verify_secret("websec-service-decoy", None) is False


def test_scopes_come_back_in_the_documented_order_and_unknown_ones_are_refused():
    assert security.parse_scopes(["scans:read", "clients:read"]) == ["clients:read", "scans:read"]
    assert security.parse_scopes([]) == []
    with pytest.raises(ValueError, match="unknown scope 'admin'"):
        security.parse_scopes(["clients:read", "admin"])


# --- settings -------------------------------------------------------------------------------------------------


def test_settings_default_to_the_cli_crawl_limits(tmp_path):
    settings = config.Settings.from_env({"WEBSEC_SERVICE_DATA_DIR": str(tmp_path)})
    assert settings.data_dir == tmp_path
    assert (settings.crawl.max_depth, settings.crawl.max_pages, settings.crawl.max_duration) == (2, 50, 60.0)
    assert settings.db_path == tmp_path / "service.db" and settings.results_dir == tmp_path / "results"


def test_settings_read_the_crawl_limits_from_the_environment(tmp_path):
    env = {
        "WEBSEC_SERVICE_DATA_DIR": str(tmp_path),
        "WEBSEC_SERVICE_CRAWL_DEPTH": "0",
        "WEBSEC_SERVICE_CRAWL_MAX_PAGES": "7",
        "WEBSEC_SERVICE_CRAWL_MAX_DURATION": "12.5",
    }
    crawl = config.Settings.from_env(env).crawl
    assert (crawl.max_depth, crawl.max_pages, crawl.max_duration) == (0, 7, 12.5)


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("WEBSEC_SERVICE_CRAWL_DEPTH", "x"),
        ("WEBSEC_SERVICE_CRAWL_MAX_PAGES", "1.5"),
        ("WEBSEC_SERVICE_CRAWL_MAX_DURATION", "soon"),
    ],
)
def test_a_bad_setting_is_an_error_at_start(name, value):
    with pytest.raises(ValueError, match=name):
        config.Settings.from_env({name: value})


@pytest.mark.parametrize("env", [{"WEBSEC_SERVICE_CRAWL_DEPTH": "-1"}, {"WEBSEC_SERVICE_CRAWL_MAX_PAGES": "0"}])
def test_limits_the_crawler_refuses_are_refused_at_start(env):
    with pytest.raises(ValueError):
        config.Settings.from_env(env)


def test_a_data_directory_given_on_the_command_line_does_not_hide_the_rest_of_the_environment(monkeypatch, tmp_path):
    monkeypatch.setenv("WEBSEC_SERVICE_CRAWL_MAX_PAGES", "7")
    monkeypatch.setenv("WEBSEC_SERVICE_DATA_DIR", str(tmp_path / "from-env"))
    settings = config.Settings.from_args(str(tmp_path / "from-flag"))
    assert settings.data_dir == tmp_path / "from-flag" and settings.crawl.max_pages == 7
    assert config.Settings.from_args(None).data_dir == tmp_path / "from-env"


def test_the_data_directory_defaults_to_a_local_folder():
    assert config.Settings.from_env({}).data_dir.name == "websec-service-data"


# --- the database ------------------------------------------------------------------------------------------------


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
def repo(tmp_path, clock):
    repository = db.Repository(tmp_path / "data" / "service.db", clock=clock)
    repository.migrate()
    return repository


def test_migrating_twice_changes_nothing(repo):
    assert repo.migrate() == repo.migrate() == db.SCHEMA_VERSION
    with sqlite3.connect(repo.path) as raw:
        assert raw.execute("SELECT version FROM schema_migrations").fetchall() == [(1,)]


def test_a_database_newer_than_the_service_is_not_touched(repo):
    with sqlite3.connect(repo.path) as raw:
        raw.execute("INSERT INTO schema_migrations VALUES (99, 'x')")
    with pytest.raises(RuntimeError, match="newer than this service"):
        repo.migrate()


def test_the_database_is_made_in_a_missing_folder(tmp_path):
    repository = db.Repository(tmp_path / "a" / "b" / "service.db")
    repository.migrate()
    assert repository.path.exists() and repository.ping()


def test_foreign_keys_are_enforced(repo):
    with pytest.raises(sqlite3.IntegrityError), repo._connect() as raw:
        raw.execute("INSERT INTO clients VALUES ('cli_x', 'ag_missing', 'n', NULL, '{}', 'active', 't', 't')")


def test_times_are_utc_with_milliseconds_and_a_z(repo, clock):
    assert repo.create_agency("A")["created_at"] == "2026-10-05T12:00:00.000Z"
    assert db.to_iso(datetime(2026, 1, 2, 3, 4, 5, 678901, tzinfo=UTC)) == "2026-01-02T03:04:05.678Z"
    seven_ahead = datetime(2026, 1, 2, 17, 0, tzinfo=timezone(timedelta(hours=7)))
    assert db.to_iso(seven_ahead) == "2026-01-02T10:00:00.000Z"  # always UTC, whatever the clock says


def test_an_agency_is_made_active_and_can_be_suspended(repo):
    agency = repo.create_agency("Agency One")
    assert ids.is_valid("agency", agency["agency_id"]) and agency["status"] == "active"
    repo.set_agency_status(agency["agency_id"], "suspended")
    assert repo.get_agency(agency["agency_id"])["status"] == "suspended"
    with pytest.raises(db.NotFound):
        repo.set_agency_status("ag_missing", "suspended")


def test_a_key_is_stored_hashed_and_returned_once(repo):
    agency = repo.create_agency("A")
    record, full = repo.create_key(agency["agency_id"], "backend", ["clients:read"], expires_in_days=30)
    assert "secret_hash" not in record and full not in str(record)
    found = repo.find_key(record["handle"])
    assert found["secret_hash"] == security.hash_secret(security.split_key(full)[1])
    assert found["scopes"] == ["clients:read"] and found["agency_status"] == "active"
    assert found["expires_at"] == "2026-11-04T12:00:00.000Z"
    listed = repo.list_keys(agency["agency_id"])
    assert listed[0]["key_id"] == record["key_id"] and "secret_hash" not in listed[0]
    assert security.split_key(full)[1].encode() not in repo.path.read_bytes()  # the secret is nowhere in the file


def test_a_key_for_an_unknown_agency_is_refused(repo):
    with pytest.raises(db.NotFound):
        repo.create_key("ag_missing", "x", [])


def test_a_key_can_be_revoked_and_stays_revoked(repo, clock):
    agency = repo.create_agency("A")
    record, _ = repo.create_key(agency["agency_id"], "k", [])
    repo.revoke_key(record["key_id"])
    first = repo.find_key(record["handle"])["revoked_at"]
    clock.advance(hours=1)
    repo.revoke_key(record["key_id"])
    assert repo.find_key(record["handle"])["revoked_at"] == first  # the first moment is kept
    with pytest.raises(db.NotFound):
        repo.revoke_key("key_missing")


def test_an_unknown_handle_finds_nothing(repo):
    assert repo.find_key("abcdefgh") is None


def test_last_used_is_written_at_most_once_a_minute(repo, clock):
    agency = repo.create_agency("A")
    record, _ = repo.create_key(agency["agency_id"], "k", [])
    assert repo.find_key(record["handle"])["last_used_at"] is None
    repo.touch_key(record["key_id"], 60)
    clock.advance(seconds=30)
    repo.touch_key(record["key_id"], 60)
    assert repo.find_key(record["handle"])["last_used_at"] == "2026-10-05T12:00:00.000Z"
    clock.advance(seconds=31)
    repo.touch_key(record["key_id"], 60)
    assert repo.find_key(record["handle"])["last_used_at"] == "2026-10-05T12:01:01.000Z"


def test_last_used_survives_a_restart_without_an_extra_write(repo, clock):
    agency = repo.create_agency("A")
    record, _ = repo.create_key(agency["agency_id"], "k", [])
    repo.touch_key(record["key_id"], 60)
    restarted = db.Repository(repo.path, clock=clock)  # a new process has no memory of the last write
    clock.advance(seconds=10)
    restarted.touch_key(record["key_id"], 60)
    assert restarted.find_key(record["handle"])["last_used_at"] == "2026-10-05T12:00:00.000Z"


@pytest.fixture
def agency(repo):
    return repo.create_agency("A")["agency_id"]


def test_a_client_is_made_and_read_back(repo, agency):
    client = repo.create_client(agency, "Acme", "acme-1", {"plan": "gold", "seats": 3})
    assert ids.is_valid("client", client["client_id"])
    assert repo.get_client(agency, client["client_id"]) == client
    assert client["metadata"] == {"plan": "gold", "seats": 3}


def test_another_agency_cannot_see_a_client(repo, agency):
    other = repo.create_agency("B")["agency_id"]
    client = repo.create_client(agency, "Acme", None, {})
    with pytest.raises(db.NotFound):
        repo.get_client(other, client["client_id"])
    with pytest.raises(db.NotFound):
        repo.update_client(other, client["client_id"], display_name="x", metadata=None)
    with pytest.raises(db.NotFound):
        repo.delete_client(other, client["client_id"])
    assert repo.list_clients(other) == []
    assert repo.get_client(agency, client["client_id"])["display_name"] == "Acme"  # untouched


def test_an_external_ref_is_unique_within_an_agency_but_not_across_agencies(repo, agency):
    other = repo.create_agency("B")["agency_id"]
    repo.create_client(agency, "One", "ref-1", {})
    with pytest.raises(db.DuplicateExternalRef):
        repo.create_client(agency, "Two", "ref-1", {})
    repo.create_client(other, "Same ref elsewhere", "ref-1", {})
    repo.create_client(agency, "No ref", None, {})
    repo.create_client(agency, "No ref either", None, {})  # any number of clients without one


def test_a_deleted_client_disappears_and_frees_its_external_ref(repo, agency):
    client = repo.create_client(agency, "One", "ref-1", {})
    repo.delete_client(agency, client["client_id"])
    with pytest.raises(db.NotFound):
        repo.get_client(agency, client["client_id"])
    assert repo.list_clients(agency) == []
    with pytest.raises(db.NotFound):
        repo.delete_client(agency, client["client_id"])  # nothing left to delete
    again = repo.create_client(agency, "One again", "ref-1", {})
    assert again["client_id"] != client["client_id"]


def test_updating_changes_only_what_is_given(repo, agency, clock):
    client = repo.create_client(agency, "Acme", "r", {"a": 1})
    clock.advance(minutes=5)
    renamed = repo.update_client(agency, client["client_id"], display_name="Acme Ltd", metadata=None)
    assert (renamed["display_name"], renamed["metadata"], renamed["external_ref"]) == ("Acme Ltd", {"a": 1}, "r")
    assert renamed["created_at"] == client["created_at"] and renamed["updated_at"] == "2026-10-05T12:05:00.000Z"
    remeta = repo.update_client(agency, client["client_id"], display_name=None, metadata={})
    assert remeta["display_name"] == "Acme Ltd" and remeta["metadata"] == {}


def test_listing_is_in_id_order_filtered_and_pages_do_not_overlap(repo, agency, clock):
    made = []
    for n in range(7):
        clock.advance(milliseconds=5)
        made.append(repo.create_client(agency, f"c{n}", f"r{n}", {})["client_id"])
    first = repo.list_clients(agency, limit=3)
    assert [c["client_id"] for c in first] == made[:4]  # limit + 1: the extra one says there is more
    second = repo.list_clients(agency, limit=3, after=made[2])
    assert [c["client_id"] for c in second] == made[3:7]
    assert [c["client_id"] for c in repo.list_clients(agency, external_ref="r5")] == [made[5]]
    assert repo.list_clients(agency, external_ref="nope") == []
    assert [c["client_id"] for c in repo.list_clients(agency, limit=100, after=made[6])] == []


def test_every_write_is_audited_without_secrets(repo, agency):
    agency_record = repo.get_agency(agency)
    record, full = repo.create_key(agency, "k", ["clients:read"])
    client = repo.create_client(agency, "Acme", "r", {"plan": "x"}, key_id=record["key_id"], ip="203.0.113.9")
    repo.update_client(
        agency, client["client_id"], display_name="B", metadata=None, key_id=record["key_id"], ip="203.0.113.9"
    )
    repo.delete_client(agency, client["client_id"], key_id=record["key_id"], ip="203.0.113.9")
    repo.revoke_key(record["key_id"])
    entries = repo.audit_entries(agency)
    assert [e["action"] for e in entries] == [
        "agency.create", "key.create", "client.create", "client.update", "client.delete", "key.revoke",
    ]  # fmt: skip
    assert entries[2]["ip"] == "203.0.113.9" and entries[2]["subject"] == client["client_id"]
    blob = str(entries)
    assert full not in blob and security.split_key(full)[1] not in blob and "Acme" not in blob
    assert agency_record["agency_id"] in blob


def test_a_failed_write_leaves_nothing_behind_not_even_its_audit_line(repo, agency):
    repo.create_client(agency, "One", "dup", {})
    before = len(repo.audit_entries())
    with pytest.raises(db.DuplicateExternalRef):
        repo.create_client(agency, "Two", "dup", {})
    assert len(repo.audit_entries()) == before
    assert len(repo.list_clients(agency)) == 1


def test_a_reader_is_not_blocked_by_a_writer(repo, agency):
    with repo._connect() as writer:  # a write transaction is open...
        writer.execute("INSERT INTO agencies VALUES ('ag_x', 'x', 'active', 't')")
        assert repo.get_agency(agency)["agency_id"] == agency  # ...and a read still works
        assert repo.get_agency("ag_x") is None  # and does not see what is not committed


def test_only_a_clash_of_external_refs_is_called_a_duplicate(repo):
    """Any other integrity problem (here an agency that does not exist) must not be reported as a duplicate."""
    with pytest.raises(sqlite3.IntegrityError) as raised:
        repo.create_client("ag_" + "0" * 26, "x", "ref", {})
    assert not isinstance(raised.value, db.DuplicateExternalRef) and "FOREIGN KEY" in str(raised.value)


def test_a_second_touch_inside_the_window_does_not_even_open_the_database(repo, monkeypatch):
    agency = repo.create_agency("A")
    record, _ = repo.create_key(agency["agency_id"], "k", [])
    repo.touch_key(record["key_id"], 60)
    opened = []
    real = repo._connect
    monkeypatch.setattr(repo, "_connect", lambda *a, **k: opened.append(1) or real(*a, **k))
    repo.touch_key(record["key_id"], 60)
    assert opened == []
