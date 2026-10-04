"""FR-QA-03c/03d: benchmarks/run.py end to end, with the real scanner against a local mock server.

No Docker and no network beyond 127.0.0.1: the benchmark apps are replaced by a mock whose
behaviour a test can flip between runs, which is how a regression is staged.
"""

from __future__ import annotations

import json

import pytest
from mock_server import Handler as MockHandler

from benchmarks import run
from websec_scanner import catalog

DIGEST = "sha256:" + "ef" * 32
IMAGE = f"example/mock@{DIGEST}"


class Flippable(MockHandler):
    """The mock, except that /.env can be switched off between two scans."""

    hide_env = False

    def do_GET(self):
        if self.path.split("?")[0] == "/.env" and Flippable.hide_env:
            return self._send(404, b"Not Found")
        return super().do_GET()


@pytest.fixture(autouse=True)
def _reset_flippable():
    Flippable.hide_env = False
    yield
    Flippable.hide_env = False


class Bench:
    """A throwaway benchmark: one app called "mock", its expected file, compose file and baseline."""

    def __init__(self, tmp_path, target):
        self.target = target
        self.expected_dir = tmp_path / "expected"
        self.expected_dir.mkdir()
        self.compose = tmp_path / "docker-compose.yml"
        self.compose.write_text(f"services:\n  mock:\n    image: {IMAGE}\n", encoding="utf-8")
        self.baseline = tmp_path / "baseline.json"
        self.results = tmp_path / "results"
        self.write_expected(reviewed=False)

    def write_expected(self, expect=(), forbid=(), reviewed=True, image=IMAGE, target=None):
        lines = [
            'app = "mock"',
            f'image = "{image}"',
            f'target = "{target or self.target}"',
            f'reviewed_by = "{"tester" if reviewed else ""}"',
        ]
        for kind, items in (("expect", expect), ("forbid", forbid)):
            for finding_id, instance_key, group in items:
                lines.append(
                    f'[[{kind}]]\nid = "{finding_id}"\ninstance_key = "{instance_key}"\n'
                    f'group = "{group}"\nreason = "test"\n'
                )
        (self.expected_dir / "mock.toml").write_text("\n".join(lines), encoding="utf-8")

    def argv(self, *extra):
        return [
            "--expected-dir", str(self.expected_dir),
            "--compose", str(self.compose),
            "--baseline", str(self.baseline),
            "--results-dir", str(self.results),
            "--timeout", "5",
            *extra,
        ]  # fmt: skip

    def main(self, *extra):
        return run.main(self.argv(*extra))

    def observed(self):
        data = json.loads((self.results / "results.json").read_text(encoding="utf-8"))
        return data["apps"]["mock"]["findings"]

    def label_everything_as_expected(self):
        self.main("--capture")
        self.write_expected(
            expect=[(f["id"], f["instance_key"], catalog.group_of_check(f["check"])) for f in self.observed()]
        )


@pytest.fixture
def bench(tmp_path, http_server):
    return Bench(tmp_path, http_server(Flippable))


# --- capture mode ---------------------------------------------------------------------------


def test_capture_lists_what_the_scanner_found_and_needs_no_review(bench):
    assert bench.main("--capture") == run.EXIT_OK
    ids = {f["id"] for f in bench.observed()}
    assert {"EXPOSURE-ENV", "COOKIE-FLAGS-MISSING"} <= ids
    summary = (bench.results / "summary.md").read_text(encoding="utf-8")
    assert "EXPOSURE-ENV" in summary
    data = json.loads((bench.results / "results.json").read_text(encoding="utf-8"))
    assert data["mode"] == "capture"
    assert not bench.baseline.exists()  # capture never writes a baseline


def test_capture_findings_carry_what_a_reviewer_needs(bench):
    bench.main("--capture")
    one = next(f for f in bench.observed() if f["id"] == "EXPOSURE-ENV")
    assert {"id", "instance_key", "severity", "check", "group", "title", "evidence", "url"} <= set(one)
    assert one["group"] == catalog.group_of_check(one["check"])


def test_capture_output_is_redacted_like_every_other_output(bench):
    bench.main("--capture")
    text = (bench.results / "results.json").read_text(encoding="utf-8")
    assert "abc123" not in text  # the mock's cookie value must not reach a CI artifact


# --- scoring mode: data problems are exit code 2 --------------------------------------------


def test_an_unreviewed_ground_truth_is_refused_in_scoring_mode(bench, capsys):
    assert bench.main() == run.EXIT_DATA
    assert "--capture" in capsys.readouterr().err  # says what to do instead


def test_unlabelled_findings_fail_the_run_and_are_listed(bench, capsys):
    bench.write_expected(expect=[])  # reviewed, but nothing classified
    assert bench.main() == run.EXIT_DATA
    err = capsys.readouterr().err
    assert "EXPOSURE-ENV" in err and "classify" in err


def test_no_baseline_is_a_data_error_that_says_how_to_make_one(bench, capsys):
    bench.label_everything_as_expected()
    assert bench.main() == run.EXIT_DATA
    assert "--update-baseline" in capsys.readouterr().err


def test_a_changed_digest_in_compose_is_a_data_error(bench, capsys):
    bench.label_everything_as_expected()
    bench.compose.write_text("services:\n  mock:\n    image: example/mock@sha256:" + "01" * 32 + "\n", encoding="utf-8")
    assert bench.main("--update-baseline") == run.EXIT_DATA
    err = capsys.readouterr().err
    assert DIGEST in err and "01" * 32 in err


def test_a_target_outside_loopback_is_refused_before_any_request(bench, monkeypatch, capsys):
    monkeypatch.setattr(run, "run_scan", lambda *a, **kw: pytest.fail("a scan was started"))
    bench.write_expected(target="https://example.com/")
    assert bench.main("--capture") == run.EXIT_DATA
    assert "loopback" in capsys.readouterr().err


def test_an_app_that_is_not_running_is_an_infrastructure_error(bench, closed_port, capsys):
    bench.write_expected(target=f"http://127.0.0.1:{closed_port}/")
    assert bench.main("--capture") == run.EXIT_DATA
    assert "could not be scanned" in capsys.readouterr().err


def test_an_unknown_app_name_is_refused(bench, capsys):
    assert bench.main("--capture", "--apps", "nonsense") == run.EXIT_DATA
    assert "nonsense" in capsys.readouterr().err


def test_an_empty_expected_dir_is_refused(bench):
    (bench.expected_dir / "mock.toml").unlink()
    assert bench.main("--capture") == run.EXIT_DATA


# --- scoring mode: the gate ------------------------------------------------------------------


def test_a_recorded_baseline_then_an_unchanged_run_passes(bench):
    bench.label_everything_as_expected()
    assert bench.main("--update-baseline") == run.EXIT_OK
    assert bench.baseline.exists()
    assert bench.main() == run.EXIT_OK
    data = json.loads((bench.results / "results.json").read_text(encoding="utf-8"))
    assert data["mode"] == "score"
    assert data["apps"]["mock"]["regressions"] == []


def test_losing_a_true_finding_fails_the_gate(bench, capsys):
    bench.label_everything_as_expected()
    assert bench.main("--update-baseline") == run.EXIT_OK
    Flippable.hide_env = True  # the scanner can no longer see /.env
    assert bench.main() == run.EXIT_REGRESSION
    assert "no longer reported" in capsys.readouterr().err
    summary = (bench.results / "summary.md").read_text(encoding="utf-8")
    assert "EXPOSURE-ENV" in summary


def test_a_new_false_positive_fails_the_gate(bench, capsys):
    Flippable.hide_env = True
    bench.main("--capture")
    keys = [(f["id"], f["instance_key"], f["group"]) for f in bench.observed()]
    bench.write_expected(
        expect=keys,
        forbid=[("EXPOSURE-ENV", ".env", "exposed-files")],  # a known non-issue on this app
    )
    assert bench.main("--update-baseline") == run.EXIT_OK
    Flippable.hide_env = False  # now it is reported: a false positive nobody had before
    assert bench.main() == run.EXIT_REGRESSION
    assert "new false positive" in capsys.readouterr().err


def test_finding_more_is_reported_as_an_improvement_and_passes(bench, capsys):
    Flippable.hide_env = True
    bench.main("--capture")
    seen = [(f["id"], f["instance_key"], f["group"]) for f in bench.observed()]
    bench.write_expected(expect=[*seen, ("EXPOSURE-ENV", ".env", "exposed-files")])  # a known miss
    assert bench.main("--update-baseline") == run.EXIT_OK
    Flippable.hide_env = False
    assert bench.main() == run.EXIT_OK
    assert "update the baseline" in capsys.readouterr().out.lower()


def test_editing_the_ground_truth_after_the_baseline_is_a_data_error(bench, capsys):
    bench.label_everything_as_expected()
    assert bench.main("--update-baseline") == run.EXIT_OK
    bench.write_expected(expect=[])  # someone dropped every entry
    assert bench.main() == run.EXIT_DATA


def test_update_baseline_refuses_to_record_while_findings_are_unlabelled(bench):
    bench.write_expected(expect=[])
    assert bench.main("--update-baseline") == run.EXIT_DATA
    assert not bench.baseline.exists()


def test_the_scan_that_decides_pass_or_fail_is_the_cli_pipeline(bench):
    # run.py must not have its own idea of a finding: it scores build_report() output, the same
    # JSON the CLI and the Web UI produce (FR-WEB-01).
    bench.main("--capture")
    from websec_scanner import cli, output

    expected = output.build_report(cli.run_scan(bench.target, timeout=5), fail_on="none")["findings"]
    assert {(f["id"], f["instance_key"]) for f in bench.observed()} == {(f["id"], f["instance_key"]) for f in expected}
