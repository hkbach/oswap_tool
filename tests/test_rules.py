"""Sprint 4 slice 1: check tables live in rules/*.json; responses are read with a size cap."""

from __future__ import annotations

import json
import time

import pytest
from conftest import QuietHandler

from owasp_scanner import cli, http_utils, rule_loader
from owasp_scanner.checks import exposure

# SRS table 4.8.1
EXPECTED_PATHS = {
    ".git/HEAD": ("EXPOSURE-GIT-HEAD", "CRITICAL"),
    ".git/config": ("EXPOSURE-GIT-CONFIG", "CRITICAL"),
    ".env": ("EXPOSURE-ENV", "CRITICAL"),
    ".env.local": ("EXPOSURE-ENV-LOCAL", "CRITICAL"),
    ".env.production": ("EXPOSURE-ENV-PRODUCTION", "CRITICAL"),
    "wp-config.php.bak": ("EXPOSURE-WP-CONFIG-BAK", "CRITICAL"),
    "config.php.bak": ("EXPOSURE-CONFIG-PHP-BAK", "CRITICAL"),
    "backup.sql": ("EXPOSURE-BACKUP-SQL", "CRITICAL"),
    "id_rsa": ("EXPOSURE-ID-RSA", "CRITICAL"),
    ".svn/entries": ("EXPOSURE-SVN-ENTRIES", "HIGH"),
    "docker-compose.yml": ("EXPOSURE-DOCKER-COMPOSE", "HIGH"),
    "backup.zip": ("EXPOSURE-BACKUP-ZIP", "HIGH"),
    "web.config": ("EXPOSURE-WEB-CONFIG", "MEDIUM"),
    "phpinfo.php": ("EXPOSURE-PHPINFO", "MEDIUM"),
    "server-status": ("EXPOSURE-SERVER-STATUS", "MEDIUM"),
    ".DS_Store": ("EXPOSURE-DS-STORE", "LOW"),
    ".well-known/security.txt": ("EXPOSURE-SECURITY-TXT", "INFO"),
}


def test_sensitive_paths_come_from_the_rules_file():
    rules = rule_loader.load_sensitive_paths()
    assert {r.path: (r.id, r.severity.value) for r in rules.paths} == EXPECTED_PATHS
    assert rules.version and rules.version == rule_loader.rules_version()


def test_report_carries_the_rules_version(http_server):
    class H(QuietHandler):
        def do_GET(self):
            self.send(404)

    report = cli.run_scan(http_server(H), timeout=5).to_dict()
    assert report["rules_version"] == rule_loader.rules_version()


def _write(tmp_path, paths, version="t1"):
    f = tmp_path / "rules.json"
    f.write_text(json.dumps({"version": version, "paths": paths}), encoding="utf-8")
    return f


GOOD = {"path": "a.txt", "id": "EXPOSURE-A", "severity": "LOW", "title": "A"}


@pytest.mark.parametrize(
    "paths, message",
    [
        ([{**GOOD, "severity": "SEVERE"}], "severity"),
        ([{k: v for k, v in GOOD.items() if k != "id"}], "id"),
        ([GOOD, {**GOOD, "path": "b.txt"}], "duplicate id"),
        ([GOOD, {**GOOD, "id": "EXPOSURE-B"}], "duplicate path"),
        ([{**GOOD, "path": "/a.txt"}], "relative"),
    ],
)
def test_invalid_rules_are_rejected_with_a_clear_message(tmp_path, paths, message):
    with pytest.raises(ValueError, match=message):
        rule_loader.load_sensitive_paths(_write(tmp_path, paths))


def test_missing_version_is_rejected(tmp_path):
    f = tmp_path / "rules.json"
    f.write_text(json.dumps({"paths": [GOOD]}), encoding="utf-8")
    with pytest.raises(ValueError, match="version"):
        rule_loader.load_sensitive_paths(f)


def test_a_new_path_needs_only_a_rules_change(http_server, tmp_path, monkeypatch):
    # FR-EXP-01 / FR-DET-13: adding a path is a data change, not a code change.
    seen = []

    class H(QuietHandler):
        def do_GET(self):
            seen.append(self.path)
            self.send(404)

    custom = rule_loader.load_sensitive_paths(_write(tmp_path, [GOOD]))
    monkeypatch.setattr(exposure, "load_sensitive_paths", lambda: custom)
    exposure.check_sensitive_paths(http_utils.build_session(timeout=2), http_server(H))
    assert "/a.txt" in seen


# --- bounded reads -------------------------------------------------------------------


class HugeHandler(QuietHandler):
    """Serves a 20 MB body, like an exposed database dump."""

    SIZE = 20 * 1024 * 1024

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Length", str(self.SIZE))
        self.end_headers()
        chunk = b"INSERT INTO t VALUES (1);\n" * 4096
        sent = 0
        try:
            while sent < self.SIZE:
                self.wfile.write(chunk)
                sent += len(chunk)
        except OSError:
            pass  # the scanner stopped reading: that is the point


def test_get_limited_reads_at_most_the_cap(http_server):
    session = http_utils.build_session(timeout=5)
    resp, body, err = http_utils.get_limited(session, http_server(HugeHandler) + "backup.sql")
    assert err is None and resp.status_code == 200
    assert 0 < len(body) <= http_utils.MAX_BODY_BYTES == 8192


def test_sensitive_path_check_does_not_download_huge_files(http_server):
    start = time.monotonic()
    exposure.check_sensitive_paths(http_utils.build_session(timeout=10), http_server(HugeHandler))
    # 17 paths x 20 MB would be 340 MB; capped reads finish quickly.
    assert time.monotonic() - start < 10
