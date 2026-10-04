"""Ground truth, scoring and the regression gate of the accuracy benchmark (FR-QA-03b/03c).

Pure functions: nothing here scans, starts Docker or touches the network, so all of it is tested
offline (tests/test_benchmark_scoring.py). ``benchmarks/run.py`` is the only caller that does I/O.

How a finding is judged
-----------------------
A finding is identified by ``(id, instance_key)``. The ground truth of an app lists, by hand:

* ``[[expect]]``: issues that really exist on that app, including ones the scanner does not
  report yet. Without those, recall would be 100% by construction (the list would only ever hold
  what the scanner already found), so the list has to come from a reviewer's own knowledge of the app.
* ``[[forbid]]``: findings known to be wrong for that app (false positives).

Every finding the scanner reports must be in one of the two lists. One that is in neither is
"unlabelled" and fails the run, so the ground truth can never silently fall behind the scanner.
"""

from __future__ import annotations

import json
import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

from websec_scanner import catalog
from websec_scanner.report import printable_text

Key = tuple[str, str]  # (finding id, instance_key)

BASELINE_SCHEMA = 1
_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})
_PINNED_IMAGE = re.compile(r"^[a-z0-9][a-z0-9./_-]*@sha256:[0-9a-f]{64}$")
_TOP_KEYS = frozenset({"app", "image", "target", "reviewed_by", "reviewed_on", "expect", "forbid"})
_ENTRY_KEYS = frozenset({"id", "instance_key", "group", "reason"})
_EPSILON = 1e-9
_EVIDENCE_LIMIT = 120


class BenchmarkDataError(Exception):
    """A problem with the benchmark's own data (ground truth, baseline, compose file, target).

    Not a regression of the scanner: the runner exits with a different code for it, so a missing
    image or an unreviewed file is never mistaken for the scanner getting worse.
    """


@dataclass(frozen=True)
class Entry:
    id: str
    instance_key: str
    group: str
    reason: str
    known_gap: bool = False  # documentation only: a real issue the scanner is not expected to find yet


@dataclass(frozen=True)
class GroundTruth:
    app: str
    image: str
    target: str
    reviewed_by: str
    reviewed_on: str
    expect: dict[Key, Entry] = field(default_factory=dict)
    forbid: dict[Key, Entry] = field(default_factory=dict)

    @property
    def reviewed(self) -> bool:
        return bool(self.reviewed_by.strip())


# --- safety guard and ground truth file ---------------------------------------------------------


def require_loopback(target: str) -> None:
    """Only apps running on this machine may be scanned (CLAUDE.md: never scan a real host)."""
    try:
        parts = urlsplit(target)
        host = (parts.hostname or "").lower()
    except ValueError:
        host, parts = "", urlsplit("")
    if parts.scheme not in ("http", "https") or host not in _LOOPBACK_HOSTS:
        raise BenchmarkDataError(
            f"target {target!r} is not on loopback: the benchmark only scans apps running on this machine"
        )


def _unknown_keys(table: dict, allowed: frozenset[str], where: str) -> None:
    extra = sorted(set(table) - allowed)
    if extra:
        raise BenchmarkDataError(f"{where}: unknown key(s) {', '.join(extra)}")


def _text(table: dict, key: str, where: str, required: bool = True) -> str:
    value = table.get(key, "")
    if not isinstance(value, str) or (required and not value.strip()):
        raise BenchmarkDataError(f"{where}: '{key}' must be a non-empty string")
    return value


def _entries(raw: object, kind: str, where: str) -> dict[Key, Entry]:
    if not isinstance(raw, list):
        raise BenchmarkDataError(f"{where}: [[{kind}]] must be a list of tables")
    entries: dict[Key, Entry] = {}
    for item in raw:
        if not isinstance(item, dict):
            raise BenchmarkDataError(f"{where}: every [[{kind}]] must be a table")
        _unknown_keys(item, _ENTRY_KEYS | ({"known_gap"} if kind == "expect" else frozenset()), f"{where} [[{kind}]]")
        label = f"{where} [[{kind}]] {item.get('id', '?')}"
        group = _text(item, "group", label)
        if group not in catalog.GROUP_IDS:
            raise BenchmarkDataError(f"{label}: group {group!r} is not one of {', '.join(catalog.GROUP_IDS)}")
        known_gap = item.get("known_gap", False)
        if not isinstance(known_gap, bool):
            raise BenchmarkDataError(f"{label}: known_gap must be true or false")
        entry = Entry(
            id=_text(item, "id", label),
            instance_key=_text(item, "instance_key", label),
            group=group,
            reason=_text(item, "reason", label),
            known_gap=known_gap,
        )
        key = (entry.id, entry.instance_key)
        if key in entries:
            raise BenchmarkDataError(f"{label}: listed twice")
        entries[key] = entry
    return entries


def load_ground_truth(path: Path) -> GroundTruth:
    """Read and strictly validate one ``benchmarks/expected/<app>.toml``."""
    where = path.name
    try:
        raw = tomllib.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise BenchmarkDataError(f"cannot read {path}: {exc}") from exc
    except tomllib.TOMLDecodeError as exc:
        raise BenchmarkDataError(f"{where} is not valid TOML: {exc}") from exc

    _unknown_keys(raw, _TOP_KEYS, where)
    app = _text(raw, "app", where)
    image = _text(raw, "image", where)
    if not _PINNED_IMAGE.match(image):
        raise BenchmarkDataError(
            f"{where}: image must be pinned by digest (name@sha256:<64 hex digits>), got {image!r}"
        )
    target = _text(raw, "target", where)
    require_loopback(target)
    expect = _entries(raw.get("expect", []), "expect", where)
    forbid = _entries(raw.get("forbid", []), "forbid", where)
    both = sorted(set(expect) & set(forbid))
    if both:
        raise BenchmarkDataError(f"{where}: {both[0][0]} at {both[0][1]} is both expected and forbidden")
    return GroundTruth(
        app=app,
        image=image,
        target=target,
        reviewed_by=_text(raw, "reviewed_by", where, required=False),
        reviewed_on=_text(raw, "reviewed_on", where, required=False),
        expect=expect,
        forbid=forbid,
    )


# --- compose file -------------------------------------------------------------------------------


def compose_images(text: str) -> dict[str, str]:
    """service -> image, read from docker-compose.yml.

    The file is kept in a plain shape (services at two spaces, ``image:`` at four) so that no YAML
    parser dependency is needed; tests/test_benchmark_guards.py keeps it that way.
    """
    images: dict[str, str] = {}
    in_services, service = False, None
    for line in text.splitlines():
        if re.match(r"^services:\s*$", line):
            in_services = True
            continue
        if in_services and re.match(r"^\S", line):
            in_services = False
        if not in_services:
            continue
        service_line = re.match(r"^  ([A-Za-z0-9_-]+):\s*$", line)
        if service_line:
            service = service_line.group(1)
            continue
        image_line = re.match(r"^    image:\s*(\S+)\s*$", line)
        if image_line and service:
            images[service] = image_line.group(1).strip("\"'")
    return images


def check_image_matches_compose(truth: GroundTruth, images: dict[str, str]) -> None:
    """FR-QA-03b: a changed digest without a re-reviewed expected file is an error, never silent."""
    if truth.app not in images:
        raise BenchmarkDataError(f"{truth.app} is not in the compose file")
    if images[truth.app] != truth.image:
        raise BenchmarkDataError(
            f"{truth.app}: the expected file is for {truth.image} but the compose file runs {images[truth.app]}. "
            "Review the ground truth for the new image, then update both"
        )


# --- scoring ------------------------------------------------------------------------------------


@dataclass
class GroupScore:
    tp: int = 0
    fp: int = 0
    fn: int = 0

    @property
    def precision(self) -> float | None:
        """None, not 0 or 1, when nothing was reported: the measure is undefined."""
        return self.tp / (self.tp + self.fp) if self.tp + self.fp else None

    @property
    def recall(self) -> float | None:
        return self.tp / (self.tp + self.fn) if self.tp + self.fn else None


@dataclass
class Score:
    tp: set[Key]
    fp: set[Key]
    fn: set[Key]
    unlabelled: set[Key]
    groups: dict[str, GroupScore]


def score(truth: GroundTruth, findings: list[dict]) -> Score:
    observed = {(f["id"], f["instance_key"]) for f in findings}
    tp = observed & set(truth.expect)
    fp = observed & set(truth.forbid)
    fn = set(truth.expect) - observed
    unlabelled = observed - set(truth.expect) - set(truth.forbid)

    groups: dict[str, GroupScore] = {e.group: GroupScore() for e in (*truth.expect.values(), *truth.forbid.values())}
    for key in tp:
        groups[truth.expect[key].group].tp += 1
    for key in fn:
        groups[truth.expect[key].group].fn += 1
    for key in fp:
        groups[truth.forbid[key].group].fp += 1
    return Score(tp=tp, fp=fp, fn=fn, unlabelled=unlabelled, groups=groups)


def _keys(keys) -> list[list[str]]:
    return [list(k) for k in sorted(keys)]


def to_record(truth: GroundTruth, result: Score) -> dict:
    """The JSON-able record of one app that goes into the baseline and the results file."""
    return {
        "image": truth.image,
        "expect": _keys(truth.expect),
        "forbid": _keys(truth.forbid),
        "tp": _keys(result.tp),
        "fp": _keys(result.fp),
        "groups": {
            name: {
                "tp": g.tp,
                "fp": g.fp,
                "fn": g.fn,
                "precision": g.precision,
                "recall": g.recall,
            }
            for name, g in sorted(result.groups.items())
        },
    }


# --- regression gate ----------------------------------------------------------------------------


@dataclass
class Comparison:
    regressions: list[str] = field(default_factory=list)
    improvements: list[str] = field(default_factory=list)


def _as_keys(rows: list) -> set[Key]:
    return {(row[0], row[1]) for row in rows}


def _describe(key: Key) -> str:
    return f"{key[0]} at {key[1]}"


def compare(baseline: dict, current: dict) -> Comparison:
    """Strict gate against the recorded baseline (product owner decision of 2026-10-04: no tolerance).

    Regressions: a finding that was true is no longer reported, a false positive that was not
    there before appears, a group's precision or recall falls. Reporting more true issues is an
    improvement: it never fails, it asks for the baseline to be updated.
    """
    if baseline["image"] != current["image"]:
        raise BenchmarkDataError(
            f"the baseline was recorded for a different image ({baseline['image']}, now {current['image']}); "
            "run --update-baseline after reviewing the results"
        )
    if baseline["expect"] != current["expect"] or baseline["forbid"] != current["forbid"]:
        raise BenchmarkDataError(
            "the ground truth changed since the baseline was recorded; review the change, then run --update-baseline"
        )

    result = Comparison()
    b_tp, c_tp = _as_keys(baseline["tp"]), _as_keys(current["tp"])
    b_fp, c_fp = _as_keys(baseline["fp"]), _as_keys(current["fp"])
    result.regressions += [f"no longer reported: {_describe(k)}" for k in sorted(b_tp - c_tp)]
    result.regressions += [f"new false positive: {_describe(k)}" for k in sorted(c_fp - b_fp)]
    for group, before in baseline["groups"].items():
        now = current["groups"].get(group, {})
        for measure in ("precision", "recall"):
            was, is_ = before[measure], now.get(measure)
            if was is None:
                continue
            if is_ is None:
                # Undefined because nothing is reported in the group any more. That is only worse when
                # something true was being reported (was > 0); a group that held nothing but false
                # positives and is now empty has improved, not regressed.
                if was > _EPSILON:
                    result.regressions.append(f"{group}: {measure} is no longer measurable (was {was:.3f})")
            elif is_ < was - _EPSILON:
                result.regressions.append(f"{group}: {measure} fell from {was:.3f} to {is_:.3f}")
    result.improvements += [f"now reported: {_describe(k)}" for k in sorted(c_tp - b_tp)]
    result.improvements += [f"false positive gone: {_describe(k)}" for k in sorted(b_fp - c_fp)]
    return result


# --- baseline file ------------------------------------------------------------------------------


def write_baseline(path: Path, records: dict[str, dict], scanner_version: str, recorded_on: str) -> None:
    """Sorted keys and a trailing newline: the same input gives the same bytes, so a PR diff is clean."""
    document = {
        "schema": BASELINE_SCHEMA,
        "scanner_version": scanner_version,
        "recorded_on": recorded_on,
        "apps": records,
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def load_baseline(path: Path) -> dict:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise BenchmarkDataError(
            f"no baseline at {path} ({exc.strerror or exc}): run with --update-baseline once the "
            "ground truth has been reviewed"
        ) from exc
    try:
        document = json.loads(text)
    except ValueError as exc:
        raise BenchmarkDataError(f"{path.name} is not valid JSON: {exc}") from exc
    if not isinstance(document, dict) or document.get("schema") != BASELINE_SCHEMA or "apps" not in document:
        raise BenchmarkDataError(f"{path.name}: unsupported schema (expected {BASELINE_SCHEMA})")
    return document


# --- markdown for the CI job summary --------------------------------------------------------------


def _cell(value: object, limit: int = 80) -> str:
    """One table cell from text that came from the scanned app: control characters made visible,
    a pipe or newline unable to break the table, and the length bounded."""
    text = printable_text(value).replace("\r", " ").replace("\n", " ").replace("|", "\\|")
    return text if len(text) <= limit else text[: limit - 1] + "…"


def markdown_observed(app: str, findings: list[dict]) -> str:
    """What the scanner reported, for the reviewer who has to label it (capture mode)."""
    lines = [
        f"### {app}: {len(findings)} finding(s) observed",
        "",
        "| Severity | Id | Instance | Title | Evidence |",
        "|---|---|---|---|---|",
    ]
    for f in findings:
        cells = (
            _cell(f.get("severity", ""), 10),
            _cell(f["id"], 60),
            _cell(f["instance_key"], 70),
            _cell(f.get("title", ""), 70),
            _cell(f.get("evidence", ""), _EVIDENCE_LIMIT),
        )
        lines.append("| " + " | ".join(cells) + " |")
    return "\n".join(lines) + "\n"


def _percent(value: float | None) -> str:
    return "n/a" if value is None else f"{value:.3f}"


def markdown_scores(app: str, result: Score, comparison: Comparison | None) -> str:
    lines = [
        f"### {app}",
        "",
        "| Group | TP | FP | FN | Precision | Recall |",
        "|---|---|---|---|---|---|",
    ]
    for name, g in sorted(result.groups.items()):
        lines.append(f"| {name} | {g.tp} | {g.fp} | {g.fn} | {_percent(g.precision)} | {_percent(g.recall)} |")
    if comparison is not None:
        for title, items in (("Regressions", comparison.regressions), ("Improvements", comparison.improvements)):
            if items:
                lines += ["", f"**{title}**", ""] + [f"- {_cell(item, 200)}" for item in items]
    return "\n".join(lines) + "\n"
