# Accuracy benchmark

Runs the scanner against two intentionally vulnerable apps in Docker, scores what it reports
against a hand-reviewed ground truth, and fails when a change makes it worse than the recorded
baseline (FR-QA-03, decision D6).

## What the numbers mean, and what they do not

This is a **regression gate**. It tells you that a change lost a finding that used to be reported
correctly, or added a wrong one. It is **not a detection rate** and must not be quoted as one in
documentation, a proposal or a report to a customer:

- Recall is only as independent as the ground truth. If the list of real issues were taken from
  the scanner's own output, recall would be perfect by construction. The list has to come from a
  reviewer's own knowledge of the app, including issues the scanner does not find yet.
- It measures only the groups a non-intrusive scanner claims to check (headers, cookies, CORS,
  exposed files, redirects, TLS). VAmPI's own flaws (injection, broken authorization) are
  API-level and outside that, and are not counted.
- Today the scanner runs its passive checks on the root path only: it has no crawler and no API
  scanning yet, so the apps' deeper surface is not measured.

## The apps

| App | License | Image | Port |
|---|---|---|---|
| [OWASP Juice Shop](https://github.com/juice-shop/juice-shop) v20.2.0 | MIT | `bkimminich/juice-shop` | 3000 |
| [VAmPI](https://github.com/erev0s/VAmPI) (vulnerable mode) | MIT | `erev0s/vampi` | 5000 |

Both are only **run as scan targets**: no code from either is copied into this repository or
shipped with the scanner. badssl.com (TLS) joins with the TLS probing package (D7), and DVWA
(GPL-3.0) and crAPI are optional later (FR-QA-03e).

**Safety.** Both apps are deliberately vulnerable.
- Every port in `docker-compose.yml` is bound to `127.0.0.1`; never publish them further.
- Images are pinned by **digest**, not tag, so each run measures the same app.
- `benchmarks.run` refuses any target that is not on loopback, before it sends a request.
- `pytest` stays offline: nothing here runs under it except the scoring logic and file checks.

## How it works

```text
python -m benchmarks.run --capture           # list what the scanner finds (for the reviewer)
python -m benchmarks.run                     # score against the ground truth and the baseline
python -m benchmarks.run --update-baseline   # record the current result as the new baseline
```

The scan is the CLI's own pipeline (`run_scan` + `build_report`), so the JSON scored is the one the
CLI and the Web UI produce, with the same redaction. Each run writes `benchmarks/results/results.json`
and `summary.md` (not committed; CI keeps them as an artifact and shows the table on the job page).

| Exit code | Meaning |
|---|---|
| `0` | pass (an improvement also exits 0 and asks you to update the baseline) |
| `1` | regression: a true finding is no longer reported, a new false positive appeared, or a group's precision or recall fell |
| `2` | a problem with the benchmark itself, not a regression: app not running, digest differs from the expected file, ground truth unreviewed or incomplete, no baseline |

## Ground truth: `expected/<app>.toml`

Each file pins the image digest it is valid for and lists, by hand:

- `[[expect]]`: an issue that really exists on the app (add `known_gap = true` for one the scanner
  does not report yet);
- `[[forbid]]`: a finding that is wrong for the app (a false positive).

Every entry gives the finding `id` and `instance_key` exactly as the scanner prints them, the check
`group`, and a `reason`. **Every finding the scanner reports must be in one of the two lists**: one
that is in neither fails the run until it is classified, so the file cannot fall behind the scanner.
A file with an empty `reviewed_by` is unreviewed and is never scored.

## Changing something

- **A new image digest:** review `expected/<app>.toml` for the new image, change the digest in both
  places, run `--update-baseline`, and commit the three files together.
- **A reviewer adds or removes an entry:** the baseline no longer matches the ground truth and the run
  exits `2`; run `--update-baseline`.
- **An improvement** (the scanner now reports more true issues): the run passes and says so; update
  the baseline so the gain is protected from now on.
- **The baseline is updated by a person, in a pull request.** It is never rewritten by CI.

## CI

`.github/workflows/benchmark.yml` runs weekly, on demand, and on a pull request that touches
`websec_scanner/**` or `benchmarks/**`. Docker is not needed on a developer machine to work on the
scoring code, but running the apps locally needs it (`docker compose -f benchmarks/docker-compose.yml up -d`,
then the commands above, then `docker compose -f benchmarks/docker-compose.yml down -v`).
