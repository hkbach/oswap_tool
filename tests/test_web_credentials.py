"""FR-WEB-07 (decision D8): the local Web UI never accepts credentials, in any form.

Authenticated scanning is a CLI/CI feature; the Web UI refuses a request that carries a
credential instead of quietly ignoring it, so a caller cannot believe a credential was used
(or was safely discarded) when it was not.
"""

from __future__ import annotations

import re
import threading

import pytest
import requests
from mock_server import Handler as MockHandler

from websec_scanner import web

FAKE_SECRET = "FAKE-SECRET-do-not-use-0000"  # noqa: S105 - obviously fake test value


@pytest.fixture
def ui():
    server = web.build_server("127.0.0.1", 0, timeout=5)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()
    server.server_close()


@pytest.fixture
def no_scan(monkeypatch):
    """Fails the test if a rejected request ever reached the scanner."""
    monkeypatch.setattr(web, "run_scan", lambda *a, **kw: pytest.fail("a rejected request started a scan"))


def scan(ui, payload):
    return requests.post(f"{ui}/api/scan", json=payload, timeout=60)


# The nine names FR-WEB-07 lists, each also in the spellings a client might use.
CREDENTIAL_NAMES = [
    "auth",
    "auth_profile_value",
    "password",
    "token",
    "cookie",
    "headers",
    "authorization",
    "api_key",
    "show_secrets",
]


def _spellings(name: str) -> list[str]:
    parts = name.split("_")
    camel = parts[0] + "".join(p.title() for p in parts[1:])
    return sorted({name, name.upper(), name.replace("_", "-"), camel})


@pytest.mark.parametrize("field", [s for n in CREDENTIAL_NAMES for s in _spellings(n)])
def test_every_credential_field_is_refused(ui, no_scan, field):
    resp = scan(ui, {"target": "https://t.example/", "authorized": True, field: FAKE_SECRET})
    assert resp.status_code == 400
    body = resp.json()
    assert body["code"] == "credential_not_accepted"
    assert body["field"] == field


@pytest.mark.parametrize("field", ["access_token", "session_id", "client_secret", "jwt", "x-api-key"])
def test_credential_like_names_outside_the_list_are_refused_as_credentials(ui, no_scan, field):
    # The declared list is the contract; names built from the redaction words
    # (token, key, session, secret, jwt...) get the same answer instead of "unknown field".
    resp = scan(ui, {"target": "https://t.example/", "authorized": True, field: FAKE_SECRET})
    assert resp.status_code == 400
    assert resp.json()["code"] == "credential_not_accepted"


def test_the_value_is_never_echoed_or_logged(ui, no_scan, capsys):
    resp = scan(ui, {"target": "https://t.example/", "authorized": True, "password": FAKE_SECRET})
    assert resp.status_code == 400
    assert FAKE_SECRET not in resp.text
    assert FAKE_SECRET not in capsys.readouterr().err  # the server's own request log


def test_an_empty_credential_is_still_refused(ui, no_scan):
    # Presence is the problem, not the value: an empty field still shows the caller expects one.
    resp = scan(ui, {"target": "https://t.example/", "authorized": True, "password": ""})
    assert resp.status_code == 400 and resp.json()["code"] == "credential_not_accepted"


def test_a_credential_is_refused_before_anything_else_is_checked(ui, no_scan):
    # Even an unauthorized request gets the credential answer, so nothing about the
    # credential depends on the rest of the payload being valid.
    resp = scan(ui, {"target": "https://t.example/", "authorized": False, "token": FAKE_SECRET})
    assert resp.status_code == 400 and resp.json()["code"] == "credential_not_accepted"


def test_the_message_points_to_the_cli(ui, no_scan):
    message = scan(ui, {"target": "https://t.example/", "authorized": True, "cookie": "x"}).json()["error"]
    assert "CLI" in message
    assert message.isascii()  # product text is English (NFR-USA-03)


def test_an_unknown_field_is_refused(ui, no_scan):
    resp = scan(ui, {"target": "https://t.example/", "authorized": True, "chekcs": ["headers"]})
    assert resp.status_code == 400
    assert resp.json()["code"] == "unknown_field"
    assert resp.json()["field"] == "chekcs"


@pytest.mark.parametrize(
    "target",
    [
        f"http://scan-user:{FAKE_SECRET}@127.0.0.1/",
        f"https://{FAKE_SECRET}@t.example/",  # a token used as the user name
        f"scan-user:{FAKE_SECRET}@t.example",  # no scheme: normalised to https:// first
    ],
)
def test_a_target_carrying_user_credentials_is_refused(ui, no_scan, capsys, target):
    resp = scan(ui, {"target": target, "authorized": True})
    assert resp.status_code == 400
    assert resp.json()["code"] == "credential_not_accepted"
    assert resp.json()["field"] == "target"
    assert FAKE_SECRET not in resp.text and FAKE_SECRET not in capsys.readouterr().err


def test_a_sensitive_query_parameter_is_still_accepted_and_redacted(ui, http_server):
    # Only userinfo is refused: ?token= may be part of a public URL, and redact() masks it.
    target = http_server(MockHandler) + f"?token={FAKE_SECRET}"
    resp = scan(ui, {"target": target, "authorized": True, "checks": ["headers"]})
    assert resp.status_code == 200
    assert FAKE_SECRET not in resp.text


def test_other_errors_keep_their_existing_shape(ui, no_scan):
    # Clients already read {"error": ...}; only the new rejections add code/field.
    resp = scan(ui, {"target": "https://t.example/", "authorized": False})
    assert resp.status_code == 400
    assert set(resp.json()) == {"error"}


def test_the_payload_the_ui_sends_is_accepted(ui, http_server):
    resp = scan(ui, {"target": http_server(MockHandler), "authorized": True, "checks": ["headers"]})
    assert resp.status_code == 200


def test_app_js_only_sends_allowed_fields():
    # If app.js grows a new field, the allowlist must grow with it, or the UI breaks.
    js = (web._STATIC_DIR / "app.js").read_text(encoding="utf-8")
    literal = re.search(r"const payload = \{([^}]*)\}", js)
    assert literal, "app.js no longer builds `const payload = {...}`; update this test"
    keys = {k.strip().split(":")[0].strip() for k in literal.group(1).split(",")}
    keys |= set(re.findall(r"payload\.(\w+)\s*=", js))
    assert keys <= web.ALLOWED_SCAN_FIELDS, keys - web.ALLOWED_SCAN_FIELDS
