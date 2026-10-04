"""Run the scanner against the benchmark apps and score it (FR-QA-03c/03d).

    python -m benchmarks.run --capture           # list what the scanner finds, for a reviewer to label
    python -m benchmarks.run                     # score against the reviewed ground truth and the baseline
    python -m benchmarks.run --update-baseline   # record the current result as the new baseline

Exit codes: 0 pass, 1 regression against the baseline, 2 a problem with the benchmark's own data or
setup (app not running, digest mismatch, unreviewed or incomplete ground truth, no baseline). The two
are kept apart so that an unreachable Docker registry is never read as the scanner getting worse.

The scan is the CLI's own pipeline (run_scan + build_report), so what is scored is exactly the JSON
the CLI and the Web UI produce, with the same redaction. Only apps on loopback are ever scanned.
"""

from __future__ import annotations

import argparse
import datetime
import json
import sys
from pathlib import Path

from benchmarks import scoring
from benchmarks.scoring import BenchmarkDataError
from websec_scanner import __version__, catalog
from websec_scanner.cli import run_scan
from websec_scanner.output import build_report
from websec_scanner.report import printable_text

EXIT_OK, EXIT_REGRESSION, EXIT_DATA = 0, 1, 2
HERE = Path(__file__).resolve().parent


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m benchmarks.run", description=__doc__.split("\n\n")[0])
    parser.add_argument("--apps", help="comma-separated app names (default: every file in --expected-dir)")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--capture", action="store_true", help="only list the findings; needs no reviewed ground truth")
    mode.add_argument("--update-baseline", action="store_true", help="record the current result as the baseline")
    parser.add_argument("--expected-dir", type=Path, default=HERE / "expected")
    parser.add_argument("--compose", type=Path, default=HERE / "docker-compose.yml")
    parser.add_argument("--baseline", type=Path, default=HERE / "baseline.json")
    parser.add_argument("--results-dir", type=Path, default=HERE / "results")
    parser.add_argument("--timeout", type=int, default=10, help="per-request timeout in seconds (default 10)")
    return parser


def _load_truths(expected_dir: Path, wanted: str | None) -> list[tuple[Path, scoring.GroundTruth]]:
    paths = sorted(expected_dir.glob("*.toml"))
    if wanted:
        names = [n.strip() for n in wanted.split(",") if n.strip()]
        unknown = sorted(set(names) - {p.stem for p in paths})
        if unknown:
            raise BenchmarkDataError(
                f"unknown app(s): {', '.join(unknown)} (known: {', '.join(p.stem for p in paths) or 'none'})"
            )
        paths = [p for p in paths if p.stem in names]
    if not paths:
        raise BenchmarkDataError(f"no expected files (*.toml) in {expected_dir}")
    return [(p, scoring.load_ground_truth(p)) for p in paths]


def _observe(truth: scoring.GroundTruth, timeout: int) -> list[dict]:
    """Scan one app and return its findings, with the group each belongs to."""
    result = run_scan(truth.target, timeout=timeout)
    if not result.baseline_fetched:
        errors = printable_text("; ".join(result.errors))[:300]
        raise BenchmarkDataError(f"{truth.app}: {truth.target} could not be scanned: {errors}")
    report = build_report(result, fail_on="none")  # the same pipeline as the CLI and the Web UI
    observed = []
    for f in report["findings"]:
        observed.append(
            {
                "id": f["id"],
                "instance_key": f["instance_key"],
                "severity": f["severity"],
                "check": f["check"],
                "group": catalog.group_of_check(f["check"]),
                "title": f["title"],
                "evidence": f["evidence"],  # already redacted by build_report()
                "url": f["url"],
                "confidence": f["confidence"],
            }
        )
    return observed


def _write(results_dir: Path, document: dict, markdown: str) -> None:
    results_dir.mkdir(parents=True, exist_ok=True)
    (results_dir / "results.json").write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (results_dir / "summary.md").write_text(markdown, encoding="utf-8")


def _run(args: argparse.Namespace) -> int:
    truths = _load_truths(args.expected_dir, args.apps)
    try:
        images = scoring.compose_images(args.compose.read_text(encoding="utf-8"))
    except OSError as exc:
        raise BenchmarkDataError(f"cannot read {args.compose}: {exc}") from exc
    for _, truth in truths:
        scoring.check_image_matches_compose(truth, images)

    if not args.capture:
        for path, truth in truths:
            if not truth.reviewed:
                raise BenchmarkDataError(
                    f"{truth.app}: the ground truth in {path.name} has not been reviewed (reviewed_by is empty). "
                    "Run with --capture, review the findings it lists, then fill in the file"
                )

    observed = {truth.app: _observe(truth, args.timeout) for _, truth in truths}
    header = f"## Accuracy benchmark (scanner {__version__})\n\n"

    if args.capture:
        document = {
            "mode": "capture",
            "scanner_version": __version__,
            "apps": {t.app: {"image": t.image, "target": t.target, "findings": observed[t.app]} for _, t in truths},
        }
        _write(
            args.results_dir, document, header + "\n".join(scoring.markdown_observed(a, f) for a, f in observed.items())
        )
        for app, findings in observed.items():
            print(f"{app}: {len(findings)} finding(s) captured in {args.results_dir / 'results.json'}")
        return EXIT_OK

    scores = {truth.app: scoring.score(truth, observed[truth.app]) for _, truth in truths}
    unlabelled = [
        f"{truth.app}: {key[0]} at {key[1]}" for path, truth in truths for key in sorted(scores[truth.app].unlabelled)
    ]
    if unlabelled:
        raise BenchmarkDataError(
            f"{len(unlabelled)} finding(s) are neither expected nor forbidden; classify each in its expected file:\n"
            + "\n".join(f"  - {line}" for line in unlabelled)
        )
    records = {truth.app: scoring.to_record(truth, scores[truth.app]) for _, truth in truths}

    if args.update_baseline:
        known = scoring.load_baseline(args.baseline)["apps"] if args.baseline.exists() else {}
        today = datetime.datetime.now(datetime.UTC).date().isoformat()
        scoring.write_baseline(args.baseline, {**known, **records}, scanner_version=__version__, recorded_on=today)
        _write(
            args.results_dir,
            {"mode": "update-baseline", "scanner_version": __version__, "apps": records},
            header + "\n".join(scoring.markdown_scores(a, s, None) for a, s in scores.items()),
        )
        print(f"baseline written to {args.baseline} for {', '.join(records)}")
        return EXIT_OK

    baseline = scoring.load_baseline(args.baseline)["apps"]
    comparisons: dict[str, scoring.Comparison] = {}
    for app, record in records.items():
        if app not in baseline:
            raise BenchmarkDataError(f"{app} has no entry in {args.baseline.name}: run with --update-baseline")
        comparisons[app] = scoring.compare(baseline[app], record)

    document = {
        "mode": "score",
        "scanner_version": __version__,
        "apps": {
            app: {
                "record": records[app],
                "regressions": comparisons[app].regressions,
                "improvements": comparisons[app].improvements,
            }
            for app in records
        },
    }
    _write(
        args.results_dir,
        document,
        header + "\n".join(scoring.markdown_scores(a, scores[a], comparisons[a]) for a in scores),
    )
    for app, comparison in comparisons.items():
        for line in comparison.regressions:
            print(f"REGRESSION {app}: {line}", file=sys.stderr)
        for line in comparison.improvements:
            print(f"IMPROVEMENT {app}: {line} (update the baseline with --update-baseline)")
    return EXIT_REGRESSION if any(c.regressions for c in comparisons.values()) else EXIT_OK


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        return _run(args)
    except BenchmarkDataError as exc:
        print(f"benchmark problem: {exc}", file=sys.stderr)
        return EXIT_DATA


if __name__ == "__main__":
    sys.exit(main())
