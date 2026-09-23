# oswap_tool

Security testing tool based on OWASP guidelines, written in Python.

> Only run this tool against systems you own or are explicitly authorized to test.

## Requirements

- Python 3.12+
- [uv](https://docs.astral.sh/uv/)

## Setup

```sh
uv sync
```

## Usage

```sh
uv run owasp-tool list-checks
uv run owasp-tool scan https://target.example --authorized
uv run owasp-tool scan https://target.example --authorized --format json -o reports/scan.json
uv run owasp-tool scan https://target.example --authorized --checks security-headers
```

`--authorized` is required and confirms you have permission to test the target.
TLS verification is always on and uses the OS trust store; pass `--ca-bundle path.pem`
if you need a custom CA (e.g. a corporate proxy).

Exit codes: `0` scan completed, `1` one or more checks failed to run, `2` usage error.

## Development

```sh
uv run pytest        # run tests
uv run ruff check .  # lint
uv run ruff format . # format
```

## Project layout

```
src/owasp_tool/
  cli.py              # argparse CLI (list-checks, scan)
  config.py           # ScanConfig (timeout, user agent, CA bundle)
  http.py             # shared httpx client factory
  models.py           # Severity, Finding, CheckError, ScanResult
  scanner.py          # runs checks, collects findings and errors
  checks/
    base.py           # Check base class
    __init__.py       # check registry (ALL_CHECKS)
    security_headers.py
  reporting/          # console and JSON reporters (REPORTERS)
tests/                # pytest tests, no network access (httpx.MockTransport)
```

## Adding a check

1. Create `src/owasp_tool/checks/<name>.py` with a `Check` subclass that sets `id`, `name`
   and `owasp`, and implements `run(client, target) -> list[Finding]`.
2. Add the class to `ALL_CHECKS` in `src/owasp_tool/checks/__init__.py`.
3. Add tests under `tests/checks/` using the `mock_client` fixture.

Checks should use the provided `client` (shared timeout, TLS and User-Agent settings) and
raise on unexpected errors; the scanner records the error and continues with other checks.

## Adding a report format

Add a module in `src/owasp_tool/reporting/` with `render(result: ScanResult) -> str` and
register it in `REPORTERS`.
