"""FR-CI-05: several targets in one run, one set of reports per target."""

from __future__ import annotations

import json
import os

import pytest
from conftest import QuietHandler

from websec_scanner import cli

# Over plain http:// every target gets TLS-NO-HTTPS-REDIRECT (HIGH), so tests that need one
# passing and one failing target restrict the scan to these groups.
GATE_GROUPS = "headers,exposed-files"


class Clean(QuietHandler):
    """Nothing above LOW in GATE_GROUPS: passes --fail-on high."""

    def do_GET(self):
        self.send(
            200,
            b"ok",
            [
                ("Strict-Transport-Security", "max-age=31536000"),
                ("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'"),
                ("X-Content-Type-Options", "nosniff"),
                ("Referrer-Policy", "no-referrer"),
                ("Permissions-Policy", "camera=()"),
            ],
        )


class Exposed(QuietHandler):
    """A target with a CRITICAL finding: fails --fail-on high."""

    def do_GET(self):
        if self.path == "/.env":
            self.send(200, b"DB_PASSWORD=fake\n")
        else:
            self.send(404)


def _main(argv, capsys):
    code = cli.main(argv)
    return code, capsys.readouterr()


def test_two_targets_on_the_command_line_are_both_scanned(http_server, tmp_path, capsys):
    a, b = http_server(Clean), http_server(Exposed)
    code, out = _main([a, b, "--yes", "--no-color", "--output-dir", str(tmp_path)], capsys)
    files = sorted(os.listdir(tmp_path))
    assert len([f for f in files if f.endswith(".json")]) == 2
    assert code == 1  # the worst target decides: one has a CRITICAL finding


def test_the_exit_code_is_the_worst_of_all_targets(http_server, tmp_path, closed_port, capsys):
    clean, unreachable = http_server(Clean), f"http://127.0.0.1:{closed_port}/"
    code, _ = _main([clean, unreachable, "--yes", "--no-color", "--timeout", "2", "--output-dir", str(tmp_path),
                     "--checks", "headers"], capsys)  # fmt: skip
    assert code == 3  # one target could not be scanned and nothing failed the gate


def test_a_targets_file_ignores_comments_and_blank_lines(http_server, tmp_path, capsys):
    a, b = http_server(Clean), http_server(Clean)
    listing = tmp_path / "targets.txt"
    listing.write_text(f"# staging targets\n{a}\n\n   {b}   # trailing comment\n", encoding="utf-8")
    out_dir = tmp_path / "out"
    _main(["--targets-file", str(listing), "--yes", "--no-color", "--output-dir", str(out_dir)], capsys)
    assert len(list(out_dir.glob("*.json"))) == 2


def test_report_files_are_named_after_the_target_and_stable(http_server, tmp_path, capsys):
    target = http_server(Clean)
    for run in ("one", "two"):
        _main([target, "--yes", "--no-color", "--output-dir", str(tmp_path / run)], capsys)
    names_one = sorted(p.name for p in (tmp_path / "one").iterdir())
    names_two = sorted(p.name for p in (tmp_path / "two").iterdir())
    assert names_one == names_two  # same target, same file name: --baseline-dir relies on it
    assert names_one[0].startswith("127.0.0.1_")


def test_formats_choose_what_is_written_per_target(http_server, tmp_path, capsys):
    _main([http_server(Clean), "--yes", "--no-color", "--output-dir", str(tmp_path),
           "--formats", "json,sarif,html,csv,junit"], capsys)  # fmt: skip
    suffixes = sorted(p.suffix for p in tmp_path.iterdir())
    assert suffixes == [".csv", ".html", ".json", ".sarif", ".xml"]


def test_single_file_outputs_are_refused_with_several_targets(http_server, tmp_path, capsys):
    a, b = http_server(Clean), http_server(Clean)
    with pytest.raises(SystemExit):
        cli.main([a, b, "--yes", "--json", str(tmp_path / "r.json")])
    assert "--output-dir" in capsys.readouterr().err


def test_a_baseline_dir_matches_each_target_to_its_own_previous_report(http_server, tmp_path, capsys):
    a, b = http_server(Exposed), http_server(Clean)
    first = tmp_path / "first"
    _main([a, b, "--yes", "--no-color", "--output-dir", str(first), "--fail-on", "none"], capsys)
    second = tmp_path / "second"
    code, _ = _main([a, b, "--yes", "--no-color", "--output-dir", str(second), "--baseline-dir", str(first)], capsys)
    assert code == 0  # nothing new on either target
    for report in second.glob("*.json"):
        data = json.loads(report.read_text(encoding="utf-8"))
        assert data["baseline"] is not None and data["gate"]["basis"] == "new"


def test_one_baseline_file_for_several_targets_is_refused(http_server, tmp_path, capsys):
    a, b = http_server(Clean), http_server(Clean)
    base = tmp_path / "b.json"
    _main([a, "--yes", "--no-color", "--json", str(base)], capsys)
    with pytest.raises(SystemExit):
        cli.main([a, b, "--yes", "--output-dir", str(tmp_path / "o"), "--baseline", str(base)])
    assert "--baseline-dir" in capsys.readouterr().err


def test_credentials_are_never_sent_to_several_different_hosts(tmp_path, capsys):
    # The same Authorization header would go to every target: a token for one site leaked to another.
    with pytest.raises(SystemExit):
        cli.main(["http://127.0.0.1:1/", "http://localhost:2/", "--yes", "--output-dir", str(tmp_path),
                  "--header", "Authorization: Bearer fake-token"])  # fmt: skip
    assert "credential" in capsys.readouterr().err.lower()


def test_a_harmless_header_is_fine_with_several_hosts(http_server, tmp_path, capsys):
    a, b = http_server(Clean), http_server(Clean)
    code, _ = _main([a, b, "--yes", "--no-color", "--output-dir", str(tmp_path), "--header", "X-Env: ci",
                     "--checks", GATE_GROUPS], capsys)  # fmt: skip
    assert code == 0


def test_parallel_runs_scan_every_target_and_print_in_input_order(http_server, tmp_path, capsys):
    targets = [http_server(Clean) for _ in range(4)]
    code, out = _main([*targets, "--yes", "--no-color", "--output-dir", str(tmp_path), "--parallel", "3"], capsys)
    assert len(list(tmp_path.glob("*.json"))) == 4
    positions = [out.out.index(f"report for: {t}") for t in targets]
    assert positions == sorted(positions)


def test_a_summary_table_lists_every_target(http_server, tmp_path, capsys):
    a, b = http_server(Clean), http_server(Exposed)
    _, out = _main([a, b, "--yes", "--no-color", "--output-dir", str(tmp_path), "--checks", GATE_GROUPS], capsys)
    summary = out.out[out.out.index("Summary of 2 targets") :]
    assert a in summary and b in summary and "fail" in summary and "pass" in summary


def test_quiet_prints_one_line_per_target(http_server, tmp_path, capsys):
    a, b = http_server(Clean), http_server(Exposed)
    _, out = _main([a, b, "--yes", "--no-color", "--quiet", "--output-dir", str(tmp_path)], capsys)
    lines = [line for line in out.out.splitlines() if line.strip()]
    assert len(lines) == 2


@pytest.mark.parametrize("bad", ["0", "-1", "65"])
def test_parallel_must_be_a_sane_number(bad, capsys):
    with pytest.raises(SystemExit):
        cli.main(["http://127.0.0.1:1/", "--yes", "--parallel", bad])
