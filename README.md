# OWASP-Aligned Non-intrusive Web Security Scanner

A Python tool (CLI + local web UI) that scans the security configuration of a
website and compares it with OWASP guidance:
[OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/),
[OWASP Top 10:2021](https://owasp.org/Top10/) and part of
[OWASP ASVS](https://owasp.org/www-project-application-security-verification-standard/).

It is a **non-intrusive configuration scanner**, not a full DAST tool: it sends
ordinary GET requests and TLS handshakes, no attack payloads (see
[Scope](#scope) and [Limitations](#limitations)).

**Contents:**
[Authorized use only](#authorized-use-only) ·
[Scope](#scope) ·
[Installation](#installation) ·
[Usage](#usage) ·
[CI/CD integration](#cicd-integration) ·
[Local web UI](#local-web-ui) ·
[Development](#development) ·
[Branch protection for `main`](#branch-protection-for-main) ·
[Project layout](#project-layout) ·
[Changelog](#changelog)

**Documentation** (project documents are written in Vietnamese):

- [`docs/SRS-owasp-scanner.md`](./docs/SRS-owasp-scanner.md) — requirements
  specification; the single requirements document, checked against the code and tests.
- [`docs/PRODUCT-BACKLOG.md`](./docs/PRODUCT-BACKLOG.md) — backlog, decisions, sprint order.
- [`CLAUDE.md`](./CLAUDE.md) — working rules for this repository.
- [`docs/report.schema.json`](./docs/report.schema.json) — JSON Schema of the `--json`
  report (`schema_version` 1.3).

## Authorized use only

The tool **only sends ordinary GET requests** and TLS handshakes. It sends no
attack payloads (no SQL injection, no brute force, no fuzzing). Scanning a
website without permission can still break the law or the owner's terms of
service. Before you run it:

- scan only domains and systems that you own, or
- get written authorization (an authorization letter or rules of engagement)
  from the system owner.

The CLI asks for confirmation before it sends anything. `--yes` skips that
prompt; use it only for targets that are already approved, for example in a CI
job that scans your own staging environment.

## Scope

The tool is not fully passive. For an `https://` target, one scan sends about
**29 GET requests** (the home page, sensitive paths and directories, two
random "soft-404" probes, `robots.txt`, `sitemap.xml`, one request with a test
`Origin` header) and **2 TLS handshakes**. It sends no exploit payloads and
changes no data on the target. Details are in SRS section 1.2.

| Check | What it looks at | OWASP mapping |
|---|---|---|
| Security headers | HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, information-leaking headers (Server, X-Powered-By, ...) | A05:2021, A03:2021 |
| Cookies | Missing Secure / HttpOnly / SameSite attributes | A05:2021 |
| TLS/SSL | Weak negotiated protocol (below TLS 1.2), weak cipher, expired / expiring / not yet valid / untrusted certificate | A02:2021 |
| HTTP to HTTPS | Whether plain HTTP is redirected to HTTPS | A02:2021 |
| CORS | `Access-Control-Allow-Origin` wildcard or reflected origin, with or without credentials | A05:2021 |
| Exposed files | `.git/`, `.env`, backups, `id_rsa`, `docker-compose.yml`, `phpinfo.php`, ... reported only when the content matches the file type | A01:2021 |
| Directory listing | Directories that list their files (`Index of /`) | A05:2021 |
| robots.txt | `Disallow:` entries that reveal sensitive-sounding paths (admin, backup, staging, ...) | A01:2021 |
| sitemap.xml | `<loc>` entries that reveal sensitive-sounding URLs | A01:2021 |

The tool only follows redirects to the same host or to the host that differs
only by `www.`, and at most 10 redirects. Requests to any other host are not
sent; each blocked host is listed in `errors`.

### Limitations

- This is a configuration scan. It does not find injection flaws (real SQLi/XSS
  testing needs active tests), business logic flaws, broken authentication at
  the application level, IDOR or SSRF. For those, use specialised tools such as
  OWASP ZAP or Burp Suite, or a manual penetration test, with a clear scope and
  permission.
- Most checks look at the home page only; there is no crawler yet.
- The TLS check looks at the protocol and cipher that were **negotiated**. It
  does not probe which older protocol versions the server still accepts.
- Findings from `robots.txt` and `sitemap.xml` are hints (`confidence: low`).
  Content signatures for exposed files are heuristics.
- If software on the scanning machine re-signs TLS (antivirus web shields, TLS
  inspection proxies), the TLS results describe that software, not the target.
  The tool warns when the certificate issuer is a known interceptor.
- Redaction is rule based: cookie values, URL parameters with sensitive
  names and credentials in URLs (`https://user:password@host`) are masked. Reports still contain URLs, headers and configuration of the
  target, so share them only with people who are allowed to see them.

A clean report does not mean that a website is secure. It means that none of
the checks above found a problem.

## Installation

Requires Python 3.12 or later. The package is not published on PyPI.

```bash
# From a clone of this repository
pip install -r requirements.txt

# Or directly from GitHub, pinned to a release tag (needs git)
pip install "git+https://github.com/hkbach/oswap_tool@v1.6.0"

# Or from the tag's source archive (no git needed)
pip install "https://github.com/hkbach/oswap_tool/archive/refs/tags/v1.6.0.tar.gz"
```

Installing the package adds two commands: `owasp-scanner` (same as
`python -m owasp_scanner`) and `owasp-scanner-web` (same as
`python -m owasp_scanner.web`).

## Usage

```bash
# Basic scan, results in the terminal (asks for authorization first)
python -m owasp_scanner https://example.com

# Skip the prompt (target already approved) and write a JSON report
python -m owasp_scanner https://example.com --yes --json report.json

# All report formats in one run
python -m owasp_scanner https://example.com --yes \
  --json report.json --sarif report.sarif --html report.html

# Slower target: longer timeout, more parallel path checks
python -m owasp_scanner https://example.com --timeout 15 --workers 8
```

| Option | Meaning |
|---|---|
| `target` | URL or hostname, for example `https://example.com` |
| `--json PATH` | Write the full JSON report (schema: `docs/report.schema.json`) |
| `--sarif PATH` | Write a SARIF 2.1.0 report, for example for GitHub code scanning |
| `--html PATH` | Write a standalone HTML report (the same file as the web UI download) |
| `--fail-on LEVEL` | Lowest severity that fails the scan with exit code `1`: `critical`, `high` (default), `medium`, `low`, `none` |
| `--ca-bundle PATH` | PEM file of CA certificates to trust instead of the OS store, for the HTTP requests and the TLS check |
| `--timeout SECONDS` | Per-request timeout (default `10`) |
| `--workers N` | Concurrent requests for the path checks (default `5`) |
| `--no-color` | No ANSI colours in the terminal output |
| `--yes`, `--i-have-authorization` | Skip the interactive authorization prompt |
| `--show-secrets` | Do not redact cookie values and sensitive URL parameters. For local debugging only; the report then carries a warning. Never use it in CI. |

**Trust store:** by default both the HTTP requests and the TLS check trust the
operating system's certificate store. `--ca-bundle`, or the environment
variables `REQUESTS_CA_BUNDLE` / `SSL_CERT_FILE`, replace it for both.

### Exit codes

| Code | Meaning |
|---|---|
| `0` | No finding at or above `--fail-on` |
| `1` | At least one finding at or above `--fail-on` (default: CRITICAL or HIGH) |
| `2` | Authorization not confirmed, or invalid arguments (for example a missing `--ca-bundle` file) |
| `3` | The scan is incomplete: the home page could not be fetched (DNS, connection, TLS, ...) |

If a scan both fails the gate and is incomplete, the exit code is `1`. With
`--fail-on none` the exit code is always `0` (reports only). The JSON report
carries the same decision in `gate` = `{fail_on, failed, incomplete}`.

## CI/CD integration

Ready-made templates are in [`examples/ci/`](./examples/ci/):

| Platform | Template | Reports kept as |
|---|---|---|
| GitHub Actions | [`github-actions.yml`](./examples/ci/github-actions.yml) | Workflow artifact, and SARIF uploaded to code scanning |
| GitLab CI | [`gitlab-ci.yml`](./examples/ci/gitlab-ci.yml) | Job artifacts (30 days) |
| Azure Pipelines | [`azure-pipelines.yml`](./examples/ci/azure-pipelines.yml) | Build artifact `owasp-scan-reports` |
| Jenkins | [`Jenkinsfile`](./examples/ci/Jenkinsfile) | Archived artifacts `owasp-report.*` |

Tests in this repository check that every template uses only real CLI options
and installs the current release tag. **The templates have not been run on the
CI systems themselves.** Try them on a non-production target first.

### Before you add the scan to a pipeline

1. **Authorization.** Get approval to scan the target, and record it where your
   team keeps such approvals. `--yes` means "the approval already exists".
2. **Network.** The runner must reach the target. The HTTP requests honour the
   usual `HTTP_PROXY` / `HTTPS_PROXY` / `NO_PROXY` variables. The TLS check opens
   direct connections and does not use a proxy. Proxy setups have not been
   tested in this repository.
3. **Release tag.** The templates install the scanner from the tag in
   `SCANNER_REF` (currently `v1.6.0`). The tag must exist in the repository;
   pinning a tag or a commit keeps the scan reproducible.
4. **Target URL.** Set `TARGET_URL` to the approved target. Scanning a
   staging environment is safer than scanning production.

### The scan step

Every template runs the same command:

```bash
python -m owasp_scanner "$TARGET_URL" --yes --no-color --fail-on high \
  --json owasp-report.json --sarif owasp-report.sarif --html owasp-report.html
```

| Exit code | What to do in CI |
|---|---|
| `0` | Pass |
| `1` | Fail: findings at or above the threshold; see the reports |
| `2` | Fail: the job is misconfigured (arguments, missing `--yes`) |
| `3` | Fail: the target could not be scanned (DNS, network, TLS); check the runner's network or the target |

Tips:

- **Keep the reports** even when the step fails. The templates do this
  (`if: always()`, `when: always`, `condition: always()`, `post { always }`).
- **Roll out gradually.** Start with `--fail-on none` or `--fail-on critical`
  to see what the scan reports, fix or accept the existing findings, then
  tighten to `high`. A `--baseline` option that fails only on new findings is
  planned (backlog FR-CI-02) but not available yet.
- **Private CA.** If the target uses an internal CA, add
  `--ca-bundle path/to/ca.pem`.
- **Secrets.** Reports redact cookie values and sensitive URL parameters by
  default. Do not add `--show-secrets` in CI.
- **Scheduling.** The GitHub and Azure templates run weekly (Monday 02:00 UTC)
  and on manual trigger; adjust the schedule to your needs.

### Platform notes

**GitHub Actions**

- Copy the template to `.github/workflows/owasp-scan.yml` in the repository
  that owns the site.
- The job needs `security-events: write` to upload SARIF. Findings then appear
  under *Security → Code scanning* with the category `owasp-scanner`.
  Code scanning is available for public repositories; private repositories
  need GitHub Code Security (part of GitHub Advanced Security).
- If you do not want the SARIF upload, delete the last step and the
  `security-events` permission.

**GitLab CI**

- Add the `owasp-scan` job to your `.gitlab-ci.yml`. It uses the `test` stage;
  change `stage:` if your pipeline has no such stage.
- The job installs `git` in the `python:3.12-slim` image before installing the
  scanner. You can use the source archive URL from
  [Installation](#installation) instead and skip the `git` install.

**Azure Pipelines**

- The template has `trigger: none` and a weekly schedule on `main`. Add a
  trigger if you also want the scan on pushes.
- Reports are written to `$(Build.ArtifactStagingDirectory)` and published as
  the `owasp-scan-reports` artifact.

**Jenkins**

- The declarative pipeline runs in a `python:3.12-slim` Docker agent (needs the
  Docker Pipeline plugin) and archives `owasp-report.*`.
- The template installs `git` with `apt-get`. Jenkins often runs the agent
  container as a non-root user, and then `apt-get` fails. In that case install
  the scanner from the source archive URL in [Installation](#installation),
  which needs no `git`, or use an image that already has `git`.

**Other CI systems:** install the package from the tag and run the scan
command above. Treat exit codes `1`, `2` and `3` as failures and keep the
report files.

## Local web UI

```bash
python -m owasp_scanner.web        # opens http://127.0.0.1:8765/
python -m owasp_scanner.web --port 9000 --timeout 15 --workers 8
python -m owasp_scanner.web --fail-on medium --ca-bundle path/to/ca.pem
```

Enter a URL, tick the authorization box and click **Scan**. The results appear
below the input: counts by severity, the gate status (the same decision as
the CLI exit code), non-fatal errors and the list of findings with a severity
filter.

- **Download Test result** (below the URL input, shown after a scan) downloads
  a standalone HTML report: embedded CSS, no scripts, works offline, printable.
  The server keeps the reports of the last 20 scans, in memory only; they are
  lost when the server stops.
- **Download JSON** downloads the same format as the CLI's `--json`.
- The web UI calls the same `run_scan()` and output pipeline as the CLI, so
  the results are identical. It always redacts secrets; there is no
  `--show-secrets` in the web UI.
- `--fail-on` and `--ca-bundle` are start-up options of the server, not
  settings in the page.
- The server listens on `127.0.0.1` by default and rejects requests with an
  unexpected `Host` or `Origin` header (protection against DNS rebinding and
  cross-site requests). It runs one scan at a time. Do not use
  `--host 0.0.0.0` unless you really need it: anyone who can reach that port
  can then start scans from your machine.
- No extra dependencies: the server uses Python's `http.server`, and the UI is
  static HTML/CSS/JS in `owasp_scanner/static/` that loads nothing from the
  internet.

## Development

Run the same steps as CI on your machine:

```bash
pip install -r requirements-dev.txt   # the package in editable mode + ruff, pytest, jsonschema
ruff check . && ruff format --check .
python -m pytest -q                   # offline; talks only to mock servers on 127.0.0.1
```

The test suite covers the acceptance scenarios AT-01 to AT-49 in SRS section 9.
It starts its own HTTP/HTTPS servers on `127.0.0.1` and generates test
certificates (expired, not yet valid, expiring, self-signed), so it needs no
internet access. Tests that need a trusted TLS handshake skip themselves when
local software intercepts TLS.

**Mock server.** `tests/mock_server.py` serves common misconfigurations
(missing headers, cookie without attributes, exposed `.env` and `.git`,
directory listing, ...) for a quick manual run without scanning a real site:

```bash
python tests/mock_server.py 8899 &
python -m owasp_scanner http://127.0.0.1:8899 --yes
```

**Golden files** (`tests/golden/`) hold the JSON, SARIF and HTML reports of
one scan of the mock server. Values that change on every run (scan id,
timestamps, port, version, fingerprints) are replaced by placeholders. After an
intended output change, regenerate them and review the diff:

```bash
UPDATE_GOLDEN=1 python -m pytest tests/test_golden.py
git diff tests/golden/
```

### Repository CI

[`.github/workflows/ci.yml`](./.github/workflows/ci.yml) runs on pushes to
`main` and `feat/**` and on pull requests to `main`:

| Job | Status check name(s) | What it does |
|---|---|---|
| `lint` | `lint` | `ruff check .` and `ruff format --check .` |
| `test` | `test (ubuntu-24.04, 3.12)`, `test (ubuntu-24.04, 3.14)`, `test (windows-latest, 3.14)` | Offline `pytest` on Ubuntu 24.04 (Python 3.12, the oldest supported, and 3.14) and Windows (3.14). |
| `min-deps` | `min-deps` | Offline `pytest` on Python 3.12 with the lowest dependency versions `pyproject.toml` allows |
| `audit` | `audit` | `pip-audit` of the runtime dependencies declared in `pyproject.toml` |
| `secrets` | `secrets` | gitleaks over the whole git history, binary checksum verified. The allowlist in `.gitleaks.toml` covers only two fake values used by the redaction tests. |

The workflow has only `contents: read` permission and uses no repository
secrets. The `audit` and `secrets` jobs need network access on the runner; the
test suite does not.

## Branch protection for `main`

The workflow reports results, but GitHub only **blocks a merge** when a
branch rule requires the checks. A repository admin sets this up once. The
check names must match exactly, and a check shows up in the search box only
after it has run at least once (open a pull request to `main` first).

Required checks:

```text
lint
min-deps
audit
secrets
test (ubuntu-24.04, 3.12)
test (ubuntu-24.04, 3.14)
test (windows-latest, 3.14)
```

The `test` check names come from the job matrix. If the matrix in
`ci.yml` changes (for example a new Python version), update the required
checks too, or pull requests will wait for a check that no longer runs.

### Option A: branch ruleset (recommended)

1. On GitHub, open the repository, then **Settings → Rules → Rulesets**.
2. Click **New ruleset → New branch ruleset**.
3. **Ruleset name:** for example `protect-main`. **Enforcement status:** `Active`.
4. **Target branches → Add target → Include default branch** (or
   *Include by pattern* `main`).
5. Enable these rules:
   - **Restrict deletions**
   - **Block force pushes**
   - **Require a pull request before merging**. Set *Required approvals* to
     `1` or more when the team has a second reviewer; `0` still forces every
     change through a pull request and its checks.
   - **Require status checks to pass**. Tick *Require branches to be up to
     date before merging*, then **Add checks** and add the seven check names
     above (choose the GitHub Actions source if asked).
6. Leave **Bypass list** empty, so the rules also apply to admins.
7. Click **Create**.

### Option B: classic branch protection rule

1. **Settings → Branches → Add classic branch protection rule**.
2. **Branch name pattern:** `main`.
3. Tick **Require a pull request before merging** (set the number of approvals
   as in option A).
4. Tick **Require status checks to pass before merging**, tick **Require
   branches to be up to date before merging**, and search for and add the seven
   checks above.
5. Tick **Do not allow bypassing the above settings**.
6. Leave *Allow force pushes* and *Allow deletions* unticked. Click **Create**.

The same classic rule with the [GitHub CLI](https://cli.github.com/), run by an
admin:

```bash
gh api --method PUT repos/hkbach/oswap_tool/branches/main/protection --input - <<'EOF'
{
  "required_status_checks": {
    "strict": true,
    "contexts": [
      "lint", "min-deps", "audit", "secrets",
      "test (ubuntu-24.04, 3.12)", "test (ubuntu-24.04, 3.14)", "test (windows-latest, 3.14)"
    ]
  },
  "enforce_admins": true,
  "required_pull_request_reviews": { "required_approving_review_count": 0 },
  "restrictions": null,
  "allow_force_pushes": false,
  "allow_deletions": false
}
EOF
```

**Check that it works:** open a pull request to `main`. The merge button must
stay disabled until all seven checks pass, and a direct `git push` to `main`
must be rejected.

Rulesets and branch protection are available for public repositories on all
GitHub plans; private repositories need a paid plan.

## Project layout

```text
owasp_scanner/
  cli.py            # CLI entry point, runs the checks (run_scan)
  output.py         # the single output pipeline: redaction, sorting, gate, exit code
  models.py         # Finding / ScanResult / Severity
  catalog.py        # CWE, confidence, references and fingerprint for each finding id
  redact.py         # secret redaction
  report.py         # terminal output and JSON
  sarif.py          # SARIF 2.1.0 output
  html_report.py    # standalone HTML report (CLI --html and the web UI download)
  http_utils.py     # shared HTTP session: timeout, User-Agent, redirect scope, trust store
  soft404.py        # soft-404 detection by response fingerprint
  rule_loader.py    # loads and validates rules/*.json
  rules/            # sensitive paths and content signatures, known TLS interceptors
  web.py            # local web UI server (python -m owasp_scanner.web)
  static/           # index.html, app.js, app.css of the web UI
  checks/
    headers.py         # security headers
    cookies.py         # cookie attributes
    tls_check.py       # TLS and certificate
    cors_check.py      # CORS misconfiguration
    exposure.py        # exposed files, directory listing, robots.txt, sitemap.xml
    redirect_check.py  # HTTP to HTTPS redirect
examples/ci/        # CI templates for GitHub Actions, GitLab CI, Azure Pipelines, Jenkins
tests/              # offline test suite, mock servers, golden files
docs/               # SRS, backlog, JSON Schema of the report
```

## Changelog

- **v1.6.0** (Sprint 7). Changes to note:
  - **Python 3.12 or later is required** (was 3.9). Development uses 3.14.
    `cryptography` 42 or later (was 41) and `requests` 2.32.3 or later (was 2.31.0)
    are required; with older `requests`, `--ca-bundle` did not apply to the HTTP
    requests.
  - **Weak TLS protocols are detected on real servers.** The measuring TLS
    connection now also reaches servers that only speak TLS 1.0/1.1, so they get
    `TLS-WEAK-PROTOCOL` (HIGH) instead of `TLS-CONN-FAILED` (INFO). **Such
    targets now fail the default gate (exit code `1`).** The trust check still
    uses strict defaults.
  - **Redaction fixes:** the same cookie set on a redirect and on the final
    response is redacted in both findings (before, the first value leaked);
    credentials in URLs (`https://user:password@host`) are masked everywhere.
  - **Cookies are read like a browser:** attributes the scanner does not check
    (`Priority`, `Partitioned`, ...) no longer create false findings for a cookie
    named after them.
  - `robots.txt` and `sitemap.xml` are read up to 512 KiB (before: in full); an
    unknown charset no longer stops the directory-listing check; IPv6 hosts
    are bracketed in URLs.
  - Web UI: returns HTTP 500 with an error message if a scan fails internally
    (before: no response); shows the same gate text as the HTML report. The
    web API adds `gate_status` and `gate_message`; the JSON report and its
    `schema_version` (1.3) are unchanged.
  - Required CI status checks: `test (ubuntu-24.04, 3.9)` is now
    `test (ubuntu-24.04, 3.12)`, and the new `min-deps` job tests the lowest
    allowed dependency versions; update branch protection.
- **v1.5.1** (Sprint 6, repository quality). No change in the tool's
  behaviour, output or exit codes.
  - CI workflow for this repository (`.github/workflows/ci.yml`, FR-QA-07):
    ruff, offline pytest (Ubuntu: Python 3.9 and 3.14; Windows: 3.14),
    `pip-audit`, gitleaks.
  - Golden files for the JSON, SARIF and HTML reports (`tests/golden/`, FR-QA-02).
  - Every finding id in the catalog is produced by at least one test (FR-QA-01).
  - The CI templates point to the `v1.5.1` tag.
- **v1.5.0** (Sprint 5, CI use). Behaviour changes to note:
  - **One trust store for both connections (FR-CI-10, fixes B1):** the HTTP
    requests now use the **operating system's certificate store** instead of
    `certifi`, like the TLS check. `--ca-bundle PATH` (or `REQUESTS_CA_BUNDLE` /
    `SSL_CERT_FILE`) replaces the default store for both.
  - **`--fail-on {critical,high,medium,low,none}`** (default `high`, FR-CI-01).
  - **Exit code `3` when the scan is incomplete** (the home page could not be
    fetched). Before, this case returned `0`, so CI could stay green although
    nothing was scanned.
  - **`--sarif PATH`** (SARIF 2.1.0, FR-RPT-02) and **`--html PATH`** (the same
    HTML report as the web UI, FR-RPT-09).
  - **JSON `schema_version` 1.3** (fields added only): `gate` =
    `{fail_on, failed, incomplete}`.
  - CI templates for GitHub Actions, GitLab CI, Azure Pipelines and Jenkins in
    `examples/ci/` (not yet run on the CI systems themselves).
- **v1.4.0** (Sprint 4, accuracy). Behaviour changes to note:
  - **Exposed-file findings are reported only when the content matches the
    file type (FR-DET-01).** HTTP 200 alone is not enough: `.git/HEAD` must
    contain `ref:`, `.env` must contain `KEY=VALUE`, `backup.zip` must start
    with `PK`, and so on. SPA catch-all pages, custom error pages and WAF block
    pages no longer cause false positives; real files on such sites are still
    found. **Expect fewer exposed-file findings.**
  - **Soft-404 detection by content fingerprint (FR-DET-02):** 2 random probes
    per scan; also recognises sites that redirect every path to `/login`.
  - **No full downloads:** each path or directory response is read up to 8 KiB.
  - **Confidence (FR-DET-03):** exposed-file findings with matching content are
    `high`.
  - **Warning when TLS is intercepted (FR-DET-16):** if the certificate was
    re-signed by antivirus software or a TLS inspection proxy (for example Avast
    Web/Mail Shield), `errors` has a warning and TLS findings get
    `confidence: low`.
  - The sensitive-path table and the list of TLS interceptors live in
    `owasp_scanner/rules/*.json`; `rules_version` now looks like
    `sensitive_paths=<v>;tls_interceptors=<v>`.
- **v1.3.0** (Sprint 3b). Behaviour changes to note:
  - **Scanning `http://` now always checks the redirect to HTTPS (FIX-09).** An
    HTTP site that does not redirect to HTTPS gets `TLS-NO-HTTPS-REDIRECT`
    (HIGH), so the **exit code becomes `1`**. If `http://` redirects to HTTPS,
    the TLS checks run on that HTTPS URL.
  - **No redirects out of scope (D4):** redirects are followed only to the
    same host or the host that differs only by `www.`; other hosts receive no
    request, and `errors` has one line per blocked host. At most 10 redirects.
  - **Headers are judged on the final response (FIX-10):** HSTS is required
    only when the final response is HTTPS; when a redirect changes the host,
    HSTS is also checked on the start host (`HDR-HSTS-MISSING-ON-START-HOST`, LOW).
  - **JSON `schema_version` 1.2** (fields added only): `final_url`,
    `redirect_chain`; new check name `hsts-start-host`.
  - **New User-Agent:** `TECHVIFY-OWASP-Scanner/<version> (+non-intrusive
    security configuration check)`. Update log or WAF filters that rely on the
    old string.
  - Product text says "Non-intrusive" instead of "Passive" (FIX-11).
  - Environment note: local software that intercepts TLS (for example Avast
    Web/Mail Shield) makes the TLS results unreliable; see SRS section 10.
- **v1.2.0** (Sprint 3). Behaviour changes to note:
  - **Secrets are redacted by default (D2):** cookie values and sensitive URL
    parameters (`token`, `key`, `session`, `password`, `sig`, ...) are replaced
    by `<redacted len=N>` in every output. The CLI has `--show-secrets` for
    local debugging; the web UI always redacts.
  - **CORS severity (D3):** `CORS-WILDCARD-WITH-CREDENTIALS` is lowered from
    CRITICAL to MEDIUM, so this combination **no longer causes exit code `1`**.
  - **JSON `schema_version` 1.1** (fields added only): `scanner_version`,
    `rules_version`, `scan_id`, `secrets_redacted`; each finding adds `cwe`,
    `confidence`, `references`, `instance_key`, `fingerprint`. The schema is in
    `docs/report.schema.json`.
  - The order of findings is stable between scans (severity, then id, then
    instance_key).
  - The CLI and the web UI share one output pipeline; the web UI reads the
    whole request body before returning an error (avoids connection resets on
    Windows).
  - Development: `pyproject.toml`, ruff, `jsonschema` (MIT); tests run on
    Python 3.9, 3.12 and 3.14.
- **v1.1.0.** Fixes for 6 issues found while reviewing SRS v1.0: (1) the TLS
  check uses 2 connections so that an expired certificate is still reported
  when the trust chain also fails; (2) `sitemap.xml` is parsed by its `<loc>`
  syntax instead of the `Disallow:` syntax of robots.txt; (3) X-Frame-Options
  is no longer reported missing when the CSP has `frame-ancestors`; (4) HSTS is
  no longer required when scanning over `http://`; (5) `Finding.id` of the
  sensitive paths is declared explicitly instead of derived from a string;
  (6) new dependency `cryptography` to read certificate dates independently of
  trust-chain validation. Details in section 0 of `docs/SRS-owasp-scanner.md`.
- **v1.0.0.** First release.
