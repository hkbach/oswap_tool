# CLAUDE.md – WebSec Scanner

Rules for Claude when working in this repo. Read alongside:

- `docs/PRODUCT-BACKLOG.md`: backlog, decisions D1–D3 (section 1.4), sprint order (section 9.1).
- `docs/SRS-websec-scanner.md`: specification of existing behavior. Do not change specified behavior without a corresponding FR.

## The product in one paragraph

A non-intrusive web security configuration scanner, written in Python. It has two entry points sharing one core:

- CLI: `python -m websec_scanner <target>`
- Local Web UI: `python -m websec_scanner.web`. Runs `http.server` at `127.0.0.1:8765`, static files are in `websec_scanner/static/`. `POST /api/scan` calls `run_scan()` in `cli.py` directly, `GET /api/report/<id>.html` uses `render_html()`.

The CLI and local Web UI have no separate server or service (decision D1). The only exception is the **agency API service** (decision D12, 2026-10-05, approved by the product owner): it lives separately in `websec_scanner/service/`, using FastAPI + SQLite via the optional `[service]` dependency group. The CLI, Web UI and core (`run_scan()`) must not import `service/` and must not depend on it (enforced by a test). Outside `service/`, do not add FastAPI, a DB, a queue or a web framework unless an FR requires it.

## Commands

```bash
pip install -r requirements-dev.txt   # pyproject.toml will exist at FR-QA-07 (Sprint 3)
ruff check . && ruff format --check . # not configured yet; mandatory from Sprint 3 (FR-QA-07)
python -m pytest -q                   # must run offline, no calls to external networks
python -m websec_scanner --help
python -m websec_scanner.web
```

## How to work

1. Work on only one FR or one small group in the current sprint at a time (backlog section 9.1).
2. Plan before coding: files to change, tests to write, risks. Wait for human approval.
3. Write tests first, code second. Tests use a local mock server and never scan a real host.
4. Keep each change small, with the ID in the commit message, for example `feat(FR-AUTH-02): add redact()`.
5. When behavior changes, update the SRS and tick the backlog in the same change.

## Mandatory rules

**Architecture**

- Python ≥ 3.12 (decided 2026-09-30; the dev environment uses 3.14), new code must have type hints.
- The CLI and Web UI must produce the same JSON. All output processing (redact, sort, `schema_version`, `fingerprint`, gating by `--fail-on`) lives in one place and is shared by both.
- Each check is a pure function in `checks/`: it takes a session/response, returns `list[Finding]`, and holds no global state.
- Lists of headers, paths and content signatures are declarative data (dict/list/YAML), not hard-coded in logic.

**Scan safety**

- The default mode sends no exploit payloads. Use only GET/HEAD/OPTIONS, with no data-modifying methods.
- Do not scan any host other than the mock server or a test app running locally.

**Secrets and evidence (D2)**

- All evidence must pass through `redact()` before being printed, written to file or returned via the API.
- The `--show-secrets` flag exists only in the CLI. The Web UI must not accept or enable this flag in any form.
- Do not log or commit secrets, real cookies, tokens or customer data. Fixtures use only obviously fake values.

**CORS severity (D3)**

| Combination | Severity |
|---|---|
| `*` + credentials | MEDIUM |
| Reflected origin + credentials | HIGH |
| Reflected origin, no credentials | MEDIUM |
| `*` alone | INFO |

**Findings and output**

- A new finding must have: a stable `id`, `severity`, `owasp_category`, `cwe`, `confidence`, `description`, `evidence`, `recommendation`, `url`.
- When unsure, lower `confidence`; do not raise severity.
- Do not break the existing JSON schema or exit codes. If a change is unavoidable, bump `schema_version` and record it in the changelog.

**Local Web UI**

- Keep the default bind of `127.0.0.1`.
- Keep the Host/Origin/Content-Type/body-size checks. Do not loosen these checks.
- The Web UI accepts no credentials in any form (D8, FR-WEB-07): `POST /api/scan` accepts only `target`, `authorized`, `checks`, `crawl` (boolean, approved by the product owner on 2026-10-04, FR-UI-14); credential fields or unknown fields are rejected with 400. Crawl limits are set by the operator at server startup, the browser cannot change them, and the Web UI always follows robots.txt. Authenticated scanning is CLI/CI only.

**API service (`service/`, D12)**

- API keys are stored only as hashes and shown exactly once at creation; do not log keys or put them in errors or audit records.
- Every query filters by the key's `agency_id`; another agency's ID returns 404 without revealing its existence (there is an isolation test).
- Blocking scans of internal addresses (SSRF) is on by default; only a developer configuration can turn it off.
- The API does not accept customer credentials for scanning; results are stored after `redact()` and `--show-secrets` output is never stored.
- Errors use `application/problem+json`; `docs/openapi.yaml` must match the code (there is a test); if the contract changes, bump the API version.

**Language**

- All product text is in English: UI, HTML report, CLI output, API error messages, finding content (SRS NFR-USA-03). The test `test_ui_text_is_english` blocks Vietnamese text in the UI's static files.
- The README is written in English (product owner decision, 2026-09-30). The remaining project documents (SRS, backlog, `docs/srs-feedback.md`, CLAUDE.md) are written in English.

**Quality and dependencies**

- Code must pass `ruff`. Do not disable rules with `noqa` without recording a reason.
- Do not add a dependency without stating the reason and checking that its license permits commercialization.
- Do not write "guaranteed safe" or "detects 100%" in reports, the README or output.

## What Claude does not do on its own

The following need human approval:

- Push, create a release, deploy.
- Delete files outside the scope of the FR.
- Add an active check (backlog E9).
- Change the architecture (add a server, DB, queue).
- Change decisions D1–D3.
