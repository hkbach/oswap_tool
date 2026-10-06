"""The operator's tool (decision D12) and the way the service is started and kept apart from the rest of the product."""

from __future__ import annotations

import io
import json
import re
import subprocess
import sys
from pathlib import Path

import pytest

from websec_scanner.service import admin, security
from websec_scanner.service import config as service_config
from websec_scanner.service.db import Repository

ROOT = Path(__file__).resolve().parents[1]
KEY = re.compile(r"wsk_[a-z0-9]{8}_[A-Za-z0-9_-]{43}")


def run(data_dir, *argv, capsys=None):
    out = io.StringIO()
    code = admin.main(["--data-dir", str(data_dir), *argv], out=out)
    return code, out.getvalue()


def make_agency(data_dir, name="Agency One"):
    _, text = run(data_dir, "create-agency", name)
    return text.split()[0]


# --- agencies and keys ----------------------------------------------------------------------------


def test_an_agency_is_made_and_listed(tmp_path):
    agency = make_agency(tmp_path, "Agency One")
    assert agency.startswith("ag_")
    code, text = run(tmp_path, "list-agencies")
    assert code == 0 and agency in text and "Agency One" in text and "active" in text


def test_nothing_listed_says_so(tmp_path):
    assert run(tmp_path, "list-agencies") == (0, "(none)\n")
    assert run(tmp_path, "list-keys", "ag_" + "0" * 26) == (0, "(none)\n")


def test_a_key_is_printed_once_on_its_own_line_and_the_warning_goes_to_stderr(tmp_path, capsys):
    agency = make_agency(tmp_path)
    code, text = run(tmp_path, "create-key", agency, "--name", "backend")
    assert code == 0 and KEY.fullmatch(text.strip())
    assert "shown once" in capsys.readouterr().err  # not on stdout, so a script that captures the key does not get it


def test_the_key_works_and_has_the_scopes_asked_for(tmp_path):
    agency = make_agency(tmp_path)
    _, text = run(
        tmp_path, "create-key", agency, "--name", "reader", "--scope", "clients:read", "--scope", "scans:read"
    )
    handle, secret = security.split_key(text.strip())
    record = Repository(tmp_path / "service.db").find_key(handle)
    assert record["scopes"] == ["clients:read", "scans:read"] and record["agency_id"] == agency
    assert security.verify_secret(secret, record["secret_hash"])


def test_a_key_defaults_to_every_scope_and_can_expire(tmp_path):
    agency = make_agency(tmp_path)
    _, text = run(tmp_path, "create-key", agency, "--name", "k", "--expires-days", "7")
    record = Repository(tmp_path / "service.db").find_key(security.split_key(text.strip())[0])
    assert record["scopes"] == list(security.SCOPES) and record["expires_at"] is not None


def test_the_secret_of_a_key_is_nowhere_on_disk_or_in_a_listing(tmp_path):
    agency = make_agency(tmp_path)
    _, text = run(tmp_path, "create-key", agency, "--name", "k")
    secret = security.split_key(text.strip())[1]
    _, listing = run(tmp_path, "list-keys", agency)
    assert secret not in listing and "wsk_" in listing and "..." in listing
    for path in tmp_path.rglob("*"):
        if path.is_file():
            assert secret.encode() not in path.read_bytes(), path


def test_json_output_has_the_key_only_for_a_new_key(tmp_path):
    agency = json.loads(run(tmp_path, "--json", "create-agency", "A")[1])
    assert agency["status"] == "active" and "api_key" not in agency
    key = json.loads(run(tmp_path, "--json", "create-key", agency["agency_id"], "--name", "k")[1])
    assert KEY.fullmatch(key["api_key"]) and "secret_hash" not in key
    listed = json.loads(run(tmp_path, "--json", "list-keys", agency["agency_id"])[1])
    assert "api_key" not in json.dumps(listed) and "secret_hash" not in json.dumps(listed)


def test_a_key_can_be_revoked(tmp_path):
    agency = make_agency(tmp_path)
    key_id = json.loads(run(tmp_path, "--json", "create-key", agency, "--name", "k")[1])["key_id"]
    code, text = run(tmp_path, "revoke-key", key_id)
    assert code == 0 and key_id in text
    assert "revoked" in run(tmp_path, "list-keys", agency)[1]


def test_an_agency_can_be_suspended_and_activated(tmp_path):
    agency = make_agency(tmp_path)
    assert run(tmp_path, "suspend-agency", agency)[1].strip() == f"{agency} is now suspended"
    assert "suspended" in run(tmp_path, "list-agencies")[1]
    assert run(tmp_path, "activate-agency", agency)[1].strip() == f"{agency} is now active"


def test_everything_the_tool_does_is_in_the_audit_log(tmp_path):
    agency = make_agency(tmp_path)
    key_id = json.loads(run(tmp_path, "--json", "create-key", agency, "--name", "k")[1])["key_id"]
    run(tmp_path, "revoke-key", key_id)
    run(tmp_path, "suspend-agency", agency)
    actions = [e["action"] for e in Repository(tmp_path / "service.db").audit_entries(agency)]
    assert actions == ["agency.create", "key.create", "key.revoke", "agency.suspended"]


# --- refusals -------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "argv",
    [
        ["create-key", "not-an-id", "--name", "k"],
        ["create-key", "cli_" + "0" * 26, "--name", "k"],
        ["list-keys", "x"],
        ["revoke-key", "ag_" + "0" * 26],
        ["suspend-agency", "key_" + "0" * 26],
        ["create-key", "ag_" + "0" * 26],  # no --name
        ["create-key", "ag_" + "0" * 26, "--name", "k", "--scope", "admin"],
        ["create-key", "ag_" + "0" * 26, "--name", "k", "--expires-days", "0"],
        ["create-key", "ag_" + "0" * 26, "--name", "k", "--expires-days", "x"],
        ["create-agency"],
        ["create-agency", "   "],
        ["nonsense"],
        [],
    ],
)
def test_bad_arguments_are_refused_with_exit_code_2(tmp_path, argv):
    with pytest.raises(SystemExit) as exc:
        run(tmp_path, *argv)
    assert exc.value.code == 2


def test_an_id_that_looks_right_but_does_not_exist_is_an_error_not_a_crash(tmp_path, capsys):
    for argv in (
        ["create-key", "ag_" + "0" * 26, "--name", "k"],
        ["revoke-key", "key_" + "0" * 26],
        ["suspend-agency", "ag_" + "0" * 26],
    ):
        code, text = run(tmp_path, *argv)
        assert code == 2 and text == ""
    assert "not found" in capsys.readouterr().err


def test_the_tool_makes_the_data_folder_it_is_given(tmp_path):
    target = tmp_path / "new" / "place"
    run(target, "create-agency", "A")
    assert (target / "service.db").exists()


def test_the_tool_works_without_fastapi():
    code = (
        "import sys; sys.modules['fastapi'] = None; sys.modules['uvicorn'] = None; "
        "from websec_scanner.service import admin; "
        "import io, tempfile; out = io.StringIO(); "
        "rc = admin.main(['--data-dir', tempfile.mkdtemp(), 'create-agency', 'A'], out=out); "
        "assert rc == 0 and out.getvalue().startswith('ag_')"
    )
    done = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, cwd=ROOT, check=False)  # noqa: S603
    assert done.returncode == 0, done.stderr


# --- starting the service -------------------------------------------------------------------------


def test_without_the_optional_dependencies_the_service_says_what_to_install(monkeypatch, capsys):
    from websec_scanner.service import __main__ as entry

    monkeypatch.setitem(sys.modules, "uvicorn", None)
    assert entry.main([]) == 2
    assert "websec-scanner[service]" in capsys.readouterr().err


def test_a_bad_setting_stops_the_service_before_it_listens(monkeypatch, tmp_path, capsys):
    pytest.importorskip("uvicorn")
    from websec_scanner.service import __main__ as entry

    monkeypatch.setenv("WEBSEC_SERVICE_CRAWL_DEPTH", "x")
    monkeypatch.setattr("uvicorn.run", lambda *a, **k: pytest.fail("the service started with a bad setting"))
    assert entry.main(["--data-dir", str(tmp_path)]) == 2
    assert "WEBSEC_SERVICE_CRAWL_DEPTH" in capsys.readouterr().err


def test_the_service_listens_where_it_is_told_and_by_default_only_on_loopback(monkeypatch, tmp_path):
    pytest.importorskip("uvicorn")
    from websec_scanner.service import __main__ as entry

    started = {}
    monkeypatch.setattr("uvicorn.run", lambda app, **kwargs: started.update(app=app, **kwargs))
    assert entry.main(["--data-dir", str(tmp_path)]) == 0
    assert started["host"] == "127.0.0.1" and started["port"] == service_config.DEFAULT_PORT
    assert started["server_header"] is False
    started.clear()
    entry.main(["--data-dir", str(tmp_path), "--host", "0.0.0.0", "--port", "9100"])  # noqa: S104 - proves it is only on request
    assert (started["host"], started["port"]) == ("0.0.0.0", 9100)  # noqa: S104


# --- the rest of the product does not depend on the service ---------------------------------------


def test_the_cli_and_the_local_web_ui_do_not_load_the_service_or_its_dependencies():
    code = (
        "import sys; import websec_scanner.cli, websec_scanner.web; "
        "loaded = sorted(m for m in sys.modules if m.split('.')[0] in ('fastapi', 'starlette', 'uvicorn', 'pydantic') "
        "or m.startswith('websec_scanner.service')); "
        "assert not loaded, loaded"
    )
    done = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, cwd=ROOT, check=False)  # noqa: S603
    assert done.returncode == 0, done.stderr


def test_no_file_outside_the_service_imports_it():
    offenders = []
    for path in (ROOT / "websec_scanner").rglob("*.py"):
        relative = path.relative_to(ROOT / "websec_scanner")
        if relative.parts[0] == "service":
            continue
        text = path.read_text(encoding="utf-8")
        if re.search(r"^\s*(from|import)\s+[.\w]*service\b", text, flags=re.MULTILINE):
            offenders.append(str(relative))
    assert offenders == []


def test_the_service_warns_when_it_is_told_scans_may_reach_private_addresses(monkeypatch, tmp_path, capsys):
    pytest.importorskip("uvicorn")
    from websec_scanner.service import __main__ as entry

    monkeypatch.setattr("uvicorn.run", lambda app, **kwargs: None)
    monkeypatch.setenv("WEBSEC_SERVICE_ALLOW_PRIVATE_TARGETS", "1")
    assert entry.main(["--data-dir", str(tmp_path)]) == 0
    assert "WARNING" in capsys.readouterr().err
    monkeypatch.delenv("WEBSEC_SERVICE_ALLOW_PRIVATE_TARGETS")
    assert entry.main(["--data-dir", str(tmp_path)]) == 0
    assert "WARNING" not in capsys.readouterr().err  # said only when it is true
