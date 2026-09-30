"""FR-DET-01: a sensitive path is reported only when its content matches the file type."""

from __future__ import annotations

import json

import pytest
from conftest import QuietHandler

from websec_scanner import cli, http_utils, rule_loader
from websec_scanner.checks import exposure

GENERIC_HTML = b"<!DOCTYPE html><html><head><title>Welcome</title></head><body>Hello a=1</body></html>"

# One realistic body per rule; every rule must have one.
SAMPLES = {
    ".git/HEAD": b"ref: refs/heads/main\n",
    ".git/config": b"[core]\n\trepositoryformatversion = 0\n\tbare = false\n",
    ".env": b"APP_ENV=production\nDB_PASSWORD=fake-password\n",
    ".env.local": b"# local overrides\nexport API_URL=http://localhost\n",
    ".env.production": b"SECRET_KEY=fake\n",
    "wp-config.php.bak": b"<?php\ndefine( 'DB_NAME', 'wordpress' );\n",
    "config.php.bak": b"<?php\n$db_host = 'localhost';\n",
    "web.config": b'<?xml version="1.0"?>\n<configuration>\n  <system.webServer/>\n</configuration>\n',
    ".svn/entries": b"12\n\ndir\n0\n",
    ".DS_Store": b"\x00\x00\x00\x01Bud1\x00\x00\x10\x00",
    "docker-compose.yml": b"version: '3.8'\nservices:\n  db:\n    image: postgres\n",
    "backup.zip": b"PK\x03\x04\x14\x00\x00\x00\x08\x00",
    "backup.sql": b"-- MySQL dump 10.13\n--\nCREATE TABLE `users` (\n",
    "phpinfo.php": b"<!DOCTYPE html><html><head><title>PHP 8.2.1 - phpinfo()</title></head><body>PHP Version 8.2.1",
    "server-status": (
        b"<!DOCTYPE html><html><head><title>Apache Status</title></head><body><h1>Apache Server Status for x"
    ),
    "id_rsa": b"-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA\n",
    ".well-known/security.txt": b"Contact: mailto:security@example.com\nExpires: 2027-01-01T00:00:00Z\n",
}

RULES = {rule.path: rule for rule in rule_loader.load_sensitive_paths().paths}


def test_every_rule_has_a_sample():
    assert set(SAMPLES) == set(RULES)


@pytest.mark.parametrize("path", sorted(SAMPLES))
def test_signature_matches_real_content(path):
    assert RULES[path].signature.matches(SAMPLES[path])


@pytest.mark.parametrize("path", sorted(SAMPLES))
@pytest.mark.parametrize(
    "body",
    [GENERIC_HTML, b"", b"Not Found", b'{"error": "not found"}', b"<html><body>404</body></html>"],
    ids=["html", "empty", "text", "json", "html404"],
)
def test_signature_rejects_generic_responses(path, body):
    assert not RULES[path].signature.matches(body)


def test_binary_magic_must_be_at_the_start():
    assert not RULES["backup.zip"].signature.matches(b"see file PK\x03\x04")


def _serve(contents: dict[str, bytes], default: bytes | None = None):
    class H(QuietHandler):
        def do_GET(self):
            path = self.path.lstrip("/")
            if path in contents:
                self.send(200, contents[path])
            elif default is not None:
                self.send(200, default, {"Content-Type": "text/html"})
            else:
                self.send(404)

    return H


@pytest.mark.parametrize("path", sorted(SAMPLES))
def test_every_rule_is_reported_end_to_end(http_server, path):
    # The check itself, over HTTP: the rule's own id, severity and URL, nothing else.
    base = http_server(_serve({path: SAMPLES[path]}))
    findings = exposure.check_sensitive_paths(http_utils.build_session(timeout=2), base)
    assert [(f.id, f.severity.value, f.url) for f in findings] == [(RULES[path].id, RULES[path].severity, base + path)]


def test_catch_all_html_site_has_no_exposure_findings(http_server):
    findings = exposure.check_sensitive_paths(
        http_utils.build_session(timeout=2), http_server(_serve({}, GENERIC_HTML))
    )
    assert findings == []


def test_real_file_on_a_catch_all_site_is_still_found(http_server):
    # A SPA answers 200 for everything, but a real .env is still a real leak.
    base = http_server(_serve({".env": SAMPLES[".env"]}, GENERIC_HTML))
    findings = exposure.check_sensitive_paths(http_utils.build_session(timeout=2), base)
    assert [f.id for f in findings] == ["EXPOSURE-ENV"]


def test_200_with_the_wrong_content_is_not_reported(http_server):
    base = http_server(_serve({".git/HEAD": b"nothing to see", "backup.zip": b"hello"}))
    assert exposure.check_sensitive_paths(http_utils.build_session(timeout=2), base) == []


def test_evidence_never_contains_the_file_content(http_server):
    result = cli.run_scan(http_server(_serve({".env": SAMPLES[".env"], "id_rsa": SAMPLES["id_rsa"]})), timeout=5)
    exposed = [f for f in result.findings if f.id in ("EXPOSURE-ENV", "EXPOSURE-ID-RSA")]
    assert len(exposed) == 2
    for f in exposed:
        text = " ".join((f.evidence, f.description, f.title))
        assert "fake-password" not in text and "b3BlbnNzaC1rZXktdjEAAAAA" not in text
        assert "content matches" in f.evidence


def _rules_file(tmp_path, signature):
    entry = {"path": "a.txt", "id": "EXPOSURE-A", "severity": "LOW", "title": "A"}
    if signature is not None:
        entry["signature"] = signature
    f = tmp_path / "rules.json"
    f.write_text(json.dumps({"version": "t", "paths": [entry]}), encoding="utf-8")
    return f


@pytest.mark.parametrize(
    "signature, message",
    [
        (None, "signature"),
        ({"description": "x", "regex": "("}, "regex"),
        ({"description": "x"}, "regex or magic_hex"),
        ({"description": "x", "magic_hex": "zz"}, "magic_hex"),
        ({"regex": "x"}, "description"),
    ],
)
def test_invalid_signatures_are_rejected(tmp_path, signature, message):
    with pytest.raises(ValueError, match=message):
        rule_loader.load_sensitive_paths(_rules_file(tmp_path, signature))
