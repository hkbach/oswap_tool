"""FR-QA-03b/03c: the benchmark's ground truth, scoring and regression gate (benchmarks/scoring.py).

Everything here is offline and pure: findings are plain dicts, nothing is scanned.
"""

from __future__ import annotations

import textwrap

import pytest

from benchmarks import scoring
from benchmarks.scoring import BenchmarkDataError

DIGEST = "sha256:" + "ab" * 32
IMAGE = f"example/app@{DIGEST}"
SITE = "http://127.0.0.1:3000/"


def finding(finding_id, instance_key=SITE, check="headers"):
    return {
        "id": finding_id,
        "instance_key": instance_key,
        "check": check,
        "severity": "MEDIUM",
        "title": f"title of {finding_id}",
        "evidence": "e",
    }


def truth_text(expect=(), forbid=(), reviewed_by="A. Reviewer", extra=""):
    parts = [
        'app = "app"',
        f'image = "{IMAGE}"',
        f'target = "{SITE}"',
        f'reviewed_by = "{reviewed_by}"',
        'reviewed_on = "2026-10-04"',
        extra,
    ]
    for kind, items in (("expect", expect), ("forbid", forbid)):
        for fid, group in items:
            parts.append(
                f'[[{kind}]]\nid = "{fid}"\ninstance_key = "{SITE}"\ngroup = "{group}"\nreason = "because {fid}"\n'
            )
    return "\n".join(parts)


def load(tmp_path, text):
    path = tmp_path / "app.toml"
    path.write_text(text, encoding="utf-8")
    return scoring.load_ground_truth(path)


# --- ground truth file -------------------------------------------------------------------


def test_a_valid_file_loads(tmp_path):
    truth = load(tmp_path, truth_text(expect=[("A", "headers")], forbid=[("B", "cors")]))
    assert truth.app == "app" and truth.image == IMAGE and truth.target == SITE
    assert truth.reviewed is True
    assert set(truth.expect) == {("A", SITE)} and set(truth.forbid) == {("B", SITE)}
    assert truth.expect[("A", SITE)].group == "headers"


def test_an_empty_reviewer_means_unreviewed(tmp_path):
    assert load(tmp_path, truth_text(reviewed_by="  ")).reviewed is False


@pytest.mark.parametrize(
    "mutate, message",
    [
        (lambda t: t.replace('app = "app"\n', ""), "app"),
        (lambda t: t.replace(IMAGE, "example/app:latest"), "sha256"),  # a tag is not a pin
        (lambda t: t.replace(DIGEST, "sha256:abc"), "sha256"),  # not 64 hex digits
        (lambda t: t.replace(SITE, "https://example.com/", 1), "loopback"),  # only the first (target)
        (lambda t: t + '\nsurprise = "x"\n', "surprise"),  # unknown key
    ],
)
def test_a_broken_file_is_a_data_error_naming_the_problem(tmp_path, mutate, message):
    with pytest.raises(BenchmarkDataError, match=message):
        load(tmp_path, mutate(truth_text(expect=[("A", "headers")])))


def test_an_entry_needs_a_reason_and_a_real_group(tmp_path):
    base = truth_text(expect=[("A", "headers")])
    with pytest.raises(BenchmarkDataError, match="reason"):
        load(tmp_path, base.replace('reason = "because A"', 'reason = ""'))
    with pytest.raises(BenchmarkDataError, match="group"):
        load(tmp_path, base.replace('group = "headers"', 'group = "nonsense"'))
    with pytest.raises(BenchmarkDataError, match="unknown"):
        load(tmp_path, base.replace('reason = "because A"', 'reason = "x"\nsurprise = 1'))


def test_the_same_finding_cannot_be_both_expected_and_forbidden(tmp_path):
    with pytest.raises(BenchmarkDataError, match="both"):
        load(tmp_path, truth_text(expect=[("A", "headers")], forbid=[("A", "headers")]))


def test_a_duplicate_entry_is_refused(tmp_path):
    with pytest.raises(BenchmarkDataError, match="twice"):
        load(tmp_path, truth_text(expect=[("A", "headers"), ("A", "headers")]))


def test_a_missing_or_malformed_file_is_a_data_error(tmp_path):
    with pytest.raises(BenchmarkDataError, match="cannot read"):
        scoring.load_ground_truth(tmp_path / "nope.toml")
    with pytest.raises(BenchmarkDataError, match="TOML"):
        load(tmp_path, "this is = = not toml")


def test_known_gap_is_optional_documentation(tmp_path):
    text = truth_text(expect=[("A", "headers")]).replace('reason = "because A"', 'reason = "x"\nknown_gap = true')
    assert load(tmp_path, text).expect[("A", SITE)].known_gap is True
    assert load(tmp_path, truth_text(expect=[("A", "headers")])).expect[("A", SITE)].known_gap is False


# --- safety guard and compose digest -------------------------------------------------------


@pytest.mark.parametrize("target", ["http://127.0.0.1:3000/", "http://localhost:5000", "http://[::1]:8080/"])
def test_loopback_targets_are_allowed(target):
    scoring.require_loopback(target)


@pytest.mark.parametrize(
    "target",
    [
        "https://example.com/",
        "http://10.0.0.5:3000/",
        "http://0.0.0.0:3000/",
        "http://127.0.0.1.evil.example/",
        "ftp://127.0.0.1/",
        "",
    ],
)
def test_anything_else_is_refused_before_a_request_is_made(target):
    with pytest.raises(BenchmarkDataError):
        scoring.require_loopback(target)


COMPOSE = textwrap.dedent(
    f"""\
    services:
      juice-shop:
        image: bkimminich/juice-shop@{DIGEST}
        ports:
          - "127.0.0.1:3000:3000"
      vampi:
        image: erev0s/vampi@{DIGEST}
        environment:
          vulnerable: "1"
    """
)


def test_compose_images_reads_each_service_image():
    assert scoring.compose_images(COMPOSE) == {
        "juice-shop": f"bkimminich/juice-shop@{DIGEST}",
        "vampi": f"erev0s/vampi@{DIGEST}",
    }


def test_a_digest_that_differs_from_compose_is_a_data_error_naming_both(tmp_path):
    truth = load(tmp_path, truth_text())
    other = "sha256:" + "cd" * 32
    images = {"app": f"example/app@{other}"}
    with pytest.raises(BenchmarkDataError) as exc:
        scoring.check_image_matches_compose(truth, images)
    assert DIGEST in str(exc.value) and other in str(exc.value)
    scoring.check_image_matches_compose(truth, {"app": IMAGE})  # equal: fine


def test_an_app_missing_from_compose_is_a_data_error(tmp_path):
    with pytest.raises(BenchmarkDataError, match="not in the compose file"):
        scoring.check_image_matches_compose(load(tmp_path, truth_text()), {})


# --- scoring --------------------------------------------------------------------------------


def make_truth(tmp_path, expect, forbid=()):
    return load(tmp_path, truth_text(expect=expect, forbid=forbid))


def test_findings_are_classified_true_false_missed_and_unlabelled(tmp_path):
    truth = make_truth(tmp_path, expect=[("A", "headers"), ("B", "headers")], forbid=[("C", "cors")])
    result = scoring.score(truth, [finding("A"), finding("C", check="cors"), finding("D")])
    assert result.tp == {("A", SITE)}
    assert result.fn == {("B", SITE)}
    assert result.fp == {("C", SITE)}
    assert result.unlabelled == {("D", SITE)}


def test_matching_is_by_id_and_instance_key_together(tmp_path):
    truth = make_truth(tmp_path, expect=[("A", "headers")])
    result = scoring.score(truth, [finding("A", instance_key="http://127.0.0.1:3000/other")])
    assert result.tp == set() and result.fn == {("A", SITE)}
    assert result.unlabelled == {("A", "http://127.0.0.1:3000/other")}


def test_precision_and_recall_per_group(tmp_path):
    truth = make_truth(
        tmp_path,
        expect=[("H1", "headers"), ("H2", "headers"), ("H3", "headers"), ("K1", "cookies")],
        forbid=[("H9", "headers")],
    )
    result = scoring.score(truth, [finding("H1"), finding("H2"), finding("H9"), finding("K1", check="cookies")])
    headers = result.groups["headers"]
    assert (headers.tp, headers.fp, headers.fn) == (2, 1, 1)
    assert headers.precision == pytest.approx(2 / 3)
    assert headers.recall == pytest.approx(2 / 3)
    cookies = result.groups["cookies"]
    assert cookies.precision == 1.0 and cookies.recall == 1.0


def test_a_group_with_nothing_to_measure_is_none_not_zero_or_one(tmp_path):
    truth = make_truth(tmp_path, expect=[("A", "headers")])
    headers = scoring.score(truth, []).groups["headers"]
    assert headers.precision is None  # nothing was reported: precision is undefined
    assert headers.recall == 0.0
    only_forbidden = make_truth(tmp_path, expect=[], forbid=[("B", "cors")])
    cors = scoring.score(only_forbidden, []).groups["cors"]
    assert cors.precision is None and cors.recall is None


def test_unlabelled_findings_do_not_enter_the_group_numbers(tmp_path):
    truth = make_truth(tmp_path, expect=[("A", "headers")])
    result = scoring.score(truth, [finding("A"), finding("X"), finding("Y")])
    assert result.groups["headers"].precision == 1.0


def test_duplicate_observed_findings_count_once(tmp_path):
    truth = make_truth(tmp_path, expect=[("A", "headers")])
    result = scoring.score(truth, [finding("A"), finding("A")])
    assert result.groups["headers"].tp == 1


# --- records and the regression gate --------------------------------------------------------


def record_of(tmp_path, expect, forbid, observed):
    truth = make_truth(tmp_path, expect=expect, forbid=forbid)
    return scoring.to_record(truth, scoring.score(truth, observed))


EXPECT = [("A", "headers"), ("B", "headers")]
FORBID = [("C", "cors")]


def test_a_record_is_plain_sorted_json(tmp_path):
    record = record_of(tmp_path, EXPECT, FORBID, [finding("B"), finding("A"), finding("C", check="cors")])
    assert record["image"] == IMAGE
    assert record["tp"] == [["A", SITE], ["B", SITE]] and record["fp"] == [["C", SITE]]
    assert record["expect"] == [["A", SITE], ["B", SITE]] and record["forbid"] == [["C", SITE]]
    assert record["groups"]["headers"] == {"tp": 2, "fp": 0, "fn": 0, "precision": 1.0, "recall": 1.0}


def test_an_unchanged_result_has_no_regressions_and_no_improvements(tmp_path):
    record = record_of(tmp_path, EXPECT, FORBID, [finding("A"), finding("B")])
    comparison = scoring.compare(record, record)
    assert comparison.regressions == [] and comparison.improvements == []


def test_a_lost_true_finding_is_a_regression(tmp_path):
    before = record_of(tmp_path, EXPECT, FORBID, [finding("A"), finding("B")])
    after = record_of(tmp_path, EXPECT, FORBID, [finding("A")])
    comparison = scoring.compare(before, after)
    assert any("no longer reported" in r and "B" in r for r in comparison.regressions)
    assert any("recall" in r for r in comparison.regressions)  # the group number says it too


def test_a_new_false_positive_is_a_regression(tmp_path):
    before = record_of(tmp_path, EXPECT, FORBID, [finding("A"), finding("B")])
    after = record_of(tmp_path, EXPECT, FORBID, [finding("A"), finding("B"), finding("C", check="cors")])
    comparison = scoring.compare(before, after)
    assert any("new false positive" in r and "C" in r for r in comparison.regressions)


def test_a_false_positive_that_was_already_in_the_baseline_is_not_new(tmp_path):
    observed = [finding("A"), finding("B"), finding("C", check="cors")]
    record = record_of(tmp_path, EXPECT, FORBID, observed)
    assert scoring.compare(record, record).regressions == []


def test_finding_more_true_issues_is_an_improvement_not_a_failure(tmp_path):
    before = record_of(tmp_path, EXPECT, FORBID, [finding("A")])
    after = record_of(tmp_path, EXPECT, FORBID, [finding("A"), finding("B")])
    comparison = scoring.compare(before, after)
    assert comparison.regressions == []
    assert any("B" in i for i in comparison.improvements)


def test_dropping_a_false_positive_is_an_improvement(tmp_path):
    before = record_of(tmp_path, EXPECT, FORBID, [finding("A"), finding("B"), finding("C", check="cors")])
    after = record_of(tmp_path, EXPECT, FORBID, [finding("A"), finding("B")])
    comparison = scoring.compare(before, after)
    assert comparison.regressions == [] and any("C" in i for i in comparison.improvements)


def test_a_measure_that_stops_being_measurable_is_a_regression(tmp_path):
    before = record_of(tmp_path, [("A", "headers")], [], [finding("A")])
    after = record_of(tmp_path, [("A", "headers")], [], [])  # precision now undefined
    assert any("precision" in r for r in scoring.compare(before, after).regressions)


def test_a_changed_ground_truth_is_a_data_error_not_a_regression(tmp_path):
    before = record_of(tmp_path, EXPECT, FORBID, [finding("A"), finding("B")])
    after = record_of(tmp_path, EXPECT + [("D", "headers")], FORBID, [finding("A"), finding("B")])
    with pytest.raises(BenchmarkDataError, match="ground truth changed"):
        scoring.compare(before, after)


def test_a_baseline_for_another_image_is_a_data_error(tmp_path):
    before = record_of(tmp_path, EXPECT, FORBID, [finding("A")])
    after = dict(before, image="example/app@sha256:" + "cd" * 32)
    with pytest.raises(BenchmarkDataError, match="different image"):
        scoring.compare(before, after)


# --- baseline file ---------------------------------------------------------------------------


def test_the_baseline_round_trips_and_is_stable_text(tmp_path):
    record = record_of(tmp_path, EXPECT, FORBID, [finding("A")])
    path = tmp_path / "baseline.json"
    scoring.write_baseline(path, {"app": record}, scanner_version="1.2.3", recorded_on="2026-10-04")
    first = path.read_text(encoding="utf-8")
    loaded = scoring.load_baseline(path)
    assert loaded["apps"]["app"] == record
    assert loaded["scanner_version"] == "1.2.3" and loaded["recorded_on"] == "2026-10-04"
    scoring.write_baseline(path, {"app": record}, scanner_version="1.2.3", recorded_on="2026-10-04")
    assert path.read_text(encoding="utf-8") == first  # same input, same bytes: a clean diff in a PR


def test_a_missing_or_wrong_baseline_is_a_data_error(tmp_path):
    with pytest.raises(BenchmarkDataError, match="no baseline"):
        scoring.load_baseline(tmp_path / "missing.json")
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    with pytest.raises(BenchmarkDataError, match="not valid JSON"):
        scoring.load_baseline(bad)
    bad.write_text('{"schema": 99, "apps": {}}', encoding="utf-8")
    with pytest.raises(BenchmarkDataError, match="schema"):
        scoring.load_baseline(bad)


# --- markdown for the CI summary ---------------------------------------------------------------


def test_the_observed_table_is_safe_to_paste_into_a_summary():
    nasty = finding("A")
    nasty.update(title="a | b\nc", evidence="x`y\x1b[2Kz|" + "q" * 500)
    table = scoring.markdown_observed("app", [nasty])
    assert "\x1b" not in table  # terminal control characters are made visible (report.printable_text)
    body = [line for line in table.splitlines() if line.startswith("| MEDIUM")]
    assert len(body) == 1, "a newline in a field must not split the row"
    assert body[0].count("|") == body[0].count("\\|") + 6  # only the 5 columns' separators are bare pipes
    assert len(body[0]) < 400  # evidence is cut


def test_the_score_markdown_lists_groups_and_problems(tmp_path):
    truth = make_truth(tmp_path, expect=EXPECT, forbid=FORBID)
    result = scoring.score(truth, [finding("A")])
    comparison = scoring.Comparison(regressions=["lost B"], improvements=[])
    text = scoring.markdown_scores("app", result, comparison)
    assert "headers" in text and "lost B" in text
    assert "n/a" in scoring.markdown_scores("app", scoring.score(make_truth(tmp_path, [("A", "headers")]), []), None)
