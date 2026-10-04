# Non-intrusive Web Security Scanner

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

- [`docs/SRS-websec-scanner.md`](./docs/SRS-websec-scanner.md) — requirements
  specification; the single requirements document, checked against the code and tests.
- [`CLAUDE.md`](./CLAUDE.md) — working rules for this repository.
- [`docs/report.schema.json`](./docs/report.schema.json) — JSON Schema of the `--json`
  report (`schema_version` 1.8).
- [`THIRD_PARTY_LICENSES.md`](./THIRD_PARTY_LICENSES.md) — license of every
  runtime and dev dependency, direct and transitive.

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
`Origin` header) and **up to 13 TLS connections**. It sends no exploit payloads and
changes no data on the target. Details are in SRS section 1.2.

Eleven of those TLS connections are **probes** (FR-DET-04): each is one standard TLS
hello that offers a single protocol version, or a single group of weak cipher suites, to
learn whether the server accepts it. A probe reads the server's first reply and closes;
no handshake is completed and no data is sent. Because they ask for old protocol
versions on purpose, **an IDS or WAF may log them**. `--no-tls-probe` turns them off and
leaves the two connections that read and verify the certificate.

| Check | What it looks at | OWASP mapping |
|---|---|---|
| Security headers | HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, information-leaking headers (Server, X-Powered-By, ...) | A05:2021, A03:2021 |
| Cookies | Missing Secure / HttpOnly / SameSite attributes | A05:2021 |
| TLS/SSL | Weak protocol versions the server accepts (SSLv3, TLS 1.0, TLS 1.1) and weak cipher suites it accepts (no encryption, export grade, anonymous, RC4, 3DES, single DES), found by probing; expired / expiring / not yet valid / untrusted certificate | A02:2021 |
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

### Test targets (check groups)

Every scan covers eight test targets. By default all of them run; `--checks`
(CLI) or the checkboxes on the web page select a subset. A test target that
is not selected sends no request, and the reports list it as **not tested**,
so a clean report of a partial scan is not mistaken for a full one.

| Id | Test target | What it checks |
|---|---|---|
| `headers` | Security headers | HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, headers that disclose server software |
| `cookies` | Cookies | Secure, HttpOnly and SameSite attributes |
| `tls` | TLS/SSL | Protocol versions and weak cipher suites the server accepts (standard handshakes, never completed), negotiated protocol and cipher, certificate validity period and trust (up to 13 TLS connections) |
| `https-redirect` | HTTP to HTTPS redirect | Whether plain HTTP is redirected to HTTPS |
| `cors` | CORS | `Access-Control-Allow-Origin` for a test Origin, with and without credentials |
| `exposed-files` | Exposed files | `.git`, `.env`, backups, keys, ... reported only when the content matches |
| `directory-listing` | Directory listing | Common directories that return a browsable file index |
| `robots-sitemap` | robots.txt / sitemap.xml | Sensitive-sounding paths advertised to crawlers (hints, low confidence) |

The home page is always fetched, because most checks read it.
`python -m websec_scanner --list-checks` prints this list.

## Installation

Requires Python 3.12 or later. The package is not published on PyPI.

```bash
# From a clone of this repository
pip install -r requirements.txt

# Or directly from GitHub, pinned to a release tag (needs git)
pip install "git+https://github.com/hkbach/oswap_tool@v1.21.0"

# Or from the tag's source archive (no git needed)
pip install "https://github.com/hkbach/oswap_tool/archive/refs/tags/v1.21.0.tar.gz"
```

Installing the package adds two commands: `websec-scanner` (same as
`python -m websec_scanner`) and `websec-scanner-web` (same as
`python -m websec_scanner.web`).

### Docker

An official `Dockerfile` (FR-CI-04) builds a minimal image that runs the CLI as a
non-root user. Published to GHCR on every release tag (`v*`) by the
`docker-publish` job in `.github/workflows/ci.yml`, after the `docker` job has
built and smoke-tested it:

```bash
docker pull ghcr.io/hkbach/websec-scanner:v1.10.0   # or :latest
docker run --rm ghcr.io/hkbach/websec-scanner:v1.10.0 https://example.com --yes --no-color

# Write reports to the host: mount a directory and give it as the output path.
docker run --rm -v "$PWD":/data -w /data ghcr.io/hkbach/websec-scanner:v1.10.0 \
  https://example.com --yes --json report.json --html report.html

# Or build it yourself from a checkout:
docker build -t websec-scanner .
```

The image has no shell tools beyond Python; it only runs
`python -m websec_scanner`. There is no `websec-scanner-web` equivalent yet —
the web UI is meant for a trusted local machine, not a container.

**One-time setup for a repository admin:** the first `docker-publish` run
creates the GHCR package; by default a package under a personal account is
**private**. To let `docker pull` work for others, open the package at
`github.com/users/hkbach/packages/container/package/websec-scanner`, go to
**Package settings**, and change visibility to public (or link it to this
repository so its access follows the repo's own visibility).

## Usage

```bash
# Basic scan, results in the terminal (asks for authorization first)
python -m websec_scanner https://example.com

# Skip the prompt (target already approved) and write a JSON report
python -m websec_scanner https://example.com --yes --json report.json

# All report formats in one run
python -m websec_scanner https://example.com --yes \
  --json report.json --sarif report.sarif --html report.html

# Slower target: longer timeout, more parallel path checks
python -m websec_scanner https://example.com --timeout 15 --workers 8

# Only some test targets (see --list-checks)
python -m websec_scanner https://example.com --yes --checks headers,cookies,tls

# Several targets, one set of reports per target, two at a time
python -m websec_scanner https://a.example.com https://b.example.com --yes \
  --output-dir reports --formats json,sarif --parallel 2

# Everything from a config file; the command line still overrides it
python -m websec_scanner --config scanner.toml --yes
```

Every option below can also be set in a [config file](#config-file), except
`--yes`, `--show-secrets`, `--config`, `--list-checks` and `--version`.

| Option | Meaning |
|---|---|
| `target` | One or more URLs or hostnames, for example `https://example.com` |
| `--config FILE` | TOML file with any of these options (see [Config file](#config-file)) |
| `--json PATH` | Write the full JSON report (schema: `docs/report.schema.json`) |
| `--sarif PATH` | Write a SARIF 2.1.0 report, for example for GitHub code scanning |
| `--html PATH` | Write a standalone HTML report (the same file as the web UI download) |
| `--csv PATH` | Write the findings as CSV (cells that would run as a spreadsheet formula are defused) |
| `--junit PATH` | Write a JUnit XML report; it shows failures exactly when the command exits non-zero |
| `--fail-on LEVEL` | Lowest severity that fails the scan with exit code `1`: `critical`, `high` (default), `medium`, `low`, `none` |
| `--baseline FILE` | `--json` report of an earlier run: only findings new since then fail the gate |
| `--suppressions FILE` | TOML file of accepted findings, each with a reason and an expiry date |
| `--checks GROUPS` | Comma-separated test targets to run, for example `headers,tls` (default: all). See [Test targets](#test-targets-check-groups) |
| `--list-checks` | Print the test targets and exit (no target, no prompt) |
| `--ca-bundle PATH` | PEM file of CA certificates to trust instead of the OS store, for the HTTP requests and the TLS check |
| `--no-tls-probe` | Skip the TLS probes: about 11 extra standard handshakes that ask which protocol versions and weak cipher suites the server accepts (config key `tls_probe = false`) |
| `--api-spec FILE` | Show an API inventory read from an OpenAPI 3.0/3.1 or Swagger 2.0 file (`.json`, `.yaml`, `.yml`, up to 5 MB). The file is only read: nothing it names is requested (config key `api_spec`) |
| `--timeout SECONDS` | Per-request timeout (default `10`) |
| `--workers N` | Concurrent requests for the path checks (default `5`) |
| `--rate-limit N` | At most N requests per second, overall and per host (default: no limit) |
| `--max-requests N` / `--max-duration SECONDS` | Stop the scan at this many requests / seconds; the report is then marked incomplete |
| `--scope-host HOST` | Another host that counts as in scope (repeatable) |
| `--exclude REGEX` / `--exclude-host HOST` | Never request matching paths / this host (repeatable) |
| `--no-default-excludes` | Drop the built-in exclusions (logout, delete, checkout, ...) |
| `--scan-id-header` | Send `X-Scanner-Scan-Id` so the target can filter this scan out of its logs |
| `--header 'NAME: VALUE'` | Extra request header (repeatable). Credential headers are masked in every report |
| `--cookie NAME=VALUE` | Cookie to send (repeatable). Values are masked in every report |
| `--proxy URL` | `http://` proxy for every request, the TLS check included |
| `--user-agent PREFIX` | Text put in front of the scanner's User-Agent; it never replaces it |
| `--targets-file FILE` | One target per line; `#` starts a comment |
| `--output-dir DIR` / `--formats LIST` | One set of reports per target in DIR, in these formats (default `json`) |
| `--baseline-dir DIR` | A previous `--output-dir`: each target is compared with its own report there |
| `--parallel N` | Scan up to N targets at the same time (default `1`, at most `64`) |
| `--quiet` / `--verbose` | One summary line per target / also log every request to stderr (credentials masked) |
| `--no-color` | No ANSI colours in the terminal output |
| `--yes`, `--i-have-authorization` | Skip the interactive authorization prompt |
| `--show-secrets` | Do not redact cookie values and sensitive URL parameters. For local debugging only; the report then carries a warning. Never use it in CI. Credentials you pass with `--header`/`--cookie`/`--proxy` stay masked even then. |
| `--version` | Print the version and exit |

**Credentials and several targets:** a credential header or a cookie would be
sent to every target, so a run with targets on more than one host refuses
them. Scan each host in its own run.

### Config file

`--config scanner.toml` holds any of the options above under their own names
(`fail_on`, `rate_limit`, `scope_hosts`, `exclude_hosts`, `headers`, ...). The
command line overrides the file; repeatable options from both are combined.
Paths are relative to the config file. An unknown key is an error, so a typo
cannot go unnoticed.

```toml
targets = ["https://staging.example.com/"]
checks = ["headers", "tls", "cookies"]
fail_on = "medium"
rate_limit = 5
output_dir = "reports"
formats = ["json", "sarif"]

[headers]
Authorization = "Bearer ${SCANNER_TOKEN}"   # read from the environment
```

`${NAME}` is replaced from the environment, and a missing variable is an
error. A credential written into the file itself is accepted with a warning.
`--yes` and `--show-secrets` cannot be put in the file: a shared, committed
file must not turn one run's authorization into a permanent one, or switch
off redaction for every CI run.

**Trust store:** by default both the HTTP requests and the TLS check trust the
operating system's certificate store. `--ca-bundle`, or the environment
variables `REQUESTS_CA_BUNDLE` / `SSL_CERT_FILE`, replace it for both.

### API inventory

`--api-spec FILE` reads an OpenAPI 3.0/3.1 or Swagger 2.0 description of an API and lists what it
declares: the servers, the endpoints (method, path, parameters, which security schemes apply) and
the security schemes. The list is printed after the findings and is in the JSON report as `api`
(`null` when the option is not used).

```bash
python -m websec_scanner https://api.example.com --api-spec openapi.yaml --json report.json
```

What it does **not** do: it sends no request to any endpoint or server the spec names, it
does not test the API (that is not in this release), and it takes only names and structure from
the file, never an example, a default or a description, which is where a spec keeps sample
secrets. A server URL that carries credentials is masked like any other secret.

A spec is a file somebody else wrote, so it is read defensively. It is refused, before the scan
sends anything, with exit code `2` and a message that names the file, when it:

- is not `.json`, `.yaml` or `.yml`, is larger than 5 MB, is nested more than 64 levels, or
  repeats a key (parsers disagree about which one wins);
- uses YAML aliases to expand to more than 500,000 values (a few hundred bytes can stand for
  billions: the "billion laughs" file), or a YAML tag that can run code such as
  `!!python/object`;
- has a `$ref` that leaves the file's own directory or the machine: a URL (including
  `http://169.254.169.254/`), an absolute or UNC path, a drive letter, a backslash, a
  percent-escape, `..` out of the directory, a symlink out of it, a cycle, a chain deeper than 32,
  more than 10,000 references or more than 20 included files. Only `#/pointers` and relative
  paths to `.json`/`.yaml`/`.yml` files next to the spec are followed;
- describes more than 2,000 endpoints or 100 parameters on one operation (an error, never a
  silent cut).

The console shows the first 100 endpoints; the JSON report has all of them. The local web UI does
not accept a spec: a browser request carries at most 4,096 bytes, and `api_spec` is refused like
any other field the page does not send.

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
| Azure Pipelines | [`azure-pipelines.yml`](./examples/ci/azure-pipelines.yml) | Build artifact `websec-scan-reports` |
| Jenkins | [`Jenkinsfile`](./examples/ci/Jenkinsfile) | Archived artifacts `websec-report.*` |

Tests in this repository check that every template uses only real CLI options
and installs the current release tag. **The templates have not been run on the
CI systems themselves.** Try them on a non-production target first.

### Before you add the scan to a pipeline

1. **Authorization.** Get approval to scan the target, and record it where your
   team keeps such approvals. `--yes` means "the approval already exists".
2. **Network.** The runner must reach the target. Behind a proxy, pass
   `--proxy http://host:port` (credentials as `http://user:pass@host:port`):
   **every** request then goes through it, the TLS check's own handshakes
   included (they tunnel with `CONNECT`), and `NO_PROXY` from the environment
   no longer applies. Only `http://` proxies are supported; `https://` and
   SOCKS proxies are refused. Without `--proxy`, the HTTP requests still honour
   `HTTP_PROXY` / `HTTPS_PROXY` / `NO_PROXY`, but the TLS check then connects
   directly. Tested against a local test proxy only.
3. **Release tag.** The templates install the scanner from the tag in
   `SCANNER_REF` (currently `v1.21.0`). The tag must exist in the repository;
   pinning a tag or a commit keeps the scan reproducible.
4. **Target URL.** Set `TARGET_URL` to the approved target. Scanning a
   staging environment is safer than scanning production.

### The scan step

Every template runs the same command:

```bash
python -m websec_scanner "$TARGET_URL" --yes --no-color --fail-on high \
  --json websec-report.json --sarif websec-report.sarif --html websec-report.html
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
  tighten to `high`. Or keep the threshold and use `--baseline`: save one
  run's `--json` report, then pass it on the next runs so only **new**
  findings fail the job (see "Baseline and accepted findings" below).
- **Private CA.** If the target uses an internal CA, add
  `--ca-bundle path/to/ca.pem`.
- **Secrets.** Reports redact cookie values and sensitive URL parameters by
  default. Do not add `--show-secrets` in CI.
- **Scheduling.** The GitHub and Azure templates run weekly (Monday 02:00 UTC)
  and on manual trigger; adjust the schedule to your needs.

### Baseline and accepted findings

Two CLI options let a pipeline fail only on what is new, without ignoring the
findings you already know about. Neither exists in the local web UI.

**`--baseline FILE`**: the `--json` report of an earlier run. Findings already
in it are marked `unchanged` and no longer fail the gate; only `new` ones do.
The report also lists what was **fixed** since then. A finding that is missing
now is only called fixed when its check ran again and the scan finished;
otherwise (you left its group out with `--checks`, or a `--max-*` limit stopped
the scan) it is listed as **not rechecked** instead.

```bash
# once, on main: record where things stand
websec-scanner https://staging.example.com --yes --json baseline.json --fail-on none
# on every run afterwards: fail only on regressions
websec-scanner https://staging.example.com --yes --baseline baseline.json --junit scan.xml
```

**`--suppressions FILE`**: a TOML file of findings you have accepted on purpose.
Every entry needs a `reason` and an `expires` date; after that date it stops
applying and the report says so. An entry matches when every field it gives
matches: `id`, `fingerprint` (from a report), or `path` (a glob on the URL path).
A suppressed finding still appears in the report, marked, and in the summary
counts; it just does not fail the gate.

```toml
# .scannerignore.toml
[[suppress]]
id = "HDR-STRICT-TRANSPORT-SECURITY-MISSING"
reason = "HSTS is added by the CDN in front of this origin; SEC-123"
expires = 2026-12-31
```

The loader is strict: an unknown key, a missing reason or date, or an entry with
nothing to match on (which would accept every finding) rejects the whole file
before the scan starts.

**`--csv PATH`** and **`--junit PATH`** write the findings for spreadsheets and
for CI test dashboards. In the JUnit file, a finding that fails the gate is a
failed test and every other finding is a skipped test with the reason, so the
dashboard shows failures exactly when the command exits non-zero.

### Platform notes

**GitHub Actions**

- Copy the template to `.github/workflows/websec-scan.yml` in the repository
  that owns the site.
- The job needs `security-events: write` to upload SARIF. Findings then appear
  under *Security → Code scanning* with the category `websec-scanner`.
  Code scanning is available for public repositories; private repositories
  need GitHub Code Security (part of GitHub Advanced Security).
- If you do not want the SARIF upload, delete the last step and the
  `security-events` permission.

**GitLab CI**

- Add the `websec-scan` job to your `.gitlab-ci.yml`. It uses the `test` stage;
  change `stage:` if your pipeline has no such stage.
- The job installs `git` in the `python:3.12-slim` image before installing the
  scanner. You can use the source archive URL from
  [Installation](#installation) instead and skip the `git` install.

**Azure Pipelines**

- The template has `trigger: none` and a weekly schedule on `main`. Add a
  trigger if you also want the scan on pushes.
- Reports are written to `$(Build.ArtifactStagingDirectory)` and published as
  the `websec-scan-reports` artifact.

**Jenkins**

- The declarative pipeline runs in a `python:3.12-slim` Docker agent (needs the
  Docker Pipeline plugin) and archives `websec-report.*`.
- The template installs from the tag's source archive over plain HTTPS (see
  [Installation](#installation)), not with `git+https`: Jenkins' Docker
  Pipeline plugin runs the agent container as a non-root user by default, and
  `apt-get install git` (needed for a `git+https` install, like the other
  three templates use) fails there.

**Other CI systems:** install the package from the tag and run the scan
command above. Treat exit codes `1`, `2` and `3` as failures and keep the
report files.

## Local web UI

```bash
python -m websec_scanner.web        # opens http://127.0.0.1:8765/
python -m websec_scanner.web --port 9000 --timeout 15 --workers 8
python -m websec_scanner.web --fail-on medium --ca-bundle path/to/ca.pem
```

All options are set when the server starts, so a browser user cannot change
them:

| Option | Meaning |
|---|---|
| `--host ADDRESS` | Address to bind (default `127.0.0.1`; anything else also needs `--allow-remote`) |
| `--port PORT` | Port to listen on (default `8765`) |
| `--allow-remote` | Required to bind anywhere other than loopback; the server refuses to start without it |
| `--token TOKEN` | Access token required on every request when bound remotely (default: a random one, printed once) |
| `--timeout SECONDS` | Per-request timeout for scans (default `10`) |
| `--workers N` | Concurrent requests for the path checks (default `5`) |
| `--fail-on LEVEL` | Threshold behind the page's gate status, same meaning as the CLI's (default `high`) |
| `--ca-bundle PATH` | PEM file of CA certificates to trust instead of the OS store |
| `--no-tls-probe` | Skip the TLS probes for every scan this server runs |
| `--rate-limit N` | At most N requests per second per scan (default: no limit) |
| `--max-requests N` / `--max-duration SECONDS` | Stop a scan after this many requests / seconds |

The web UI never accepts credentials. A scan request may only carry `target`,
`authorized` and `checks`; a request with a password, token, cookie, header,
`authorization`, API key or `show_secrets` field, or with a `user:password@` in the
target, is refused with HTTP 400 (`credential_not_accepted`), and so is any other
field (`unknown_field`). Run authenticated scans from the CLI, with secrets in
environment variables or a config file.

The CLI's `--baseline`, `--suppressions`, `--config`, `--csv`, `--junit` and
the multi-target options have no web UI equivalent: they belong to a CI run,
not to a browser session. The JSON the web UI returns still carries their
fields, set to `null`.

The page has three steps: enter the target URL, choose the **test targets**
(all are selected by default; *Select all* / *Clear*), and confirm that you are
authorized to scan. Then click **Scan**. The results show the counts by
severity, the gate status (the same decision as the CLI exit code), which test
targets were not tested, non-fatal errors, and the findings:

- **Group by: Test target** (default) lists one collapsible section per test
  target with its severity counts and a status: *N issues*, *No issues*,
  *Not run* (selected, but it could not run, for example TLS on a plain-HTTP
  site) or *Not selected*.
- **Group by: OWASP Top 10** lists the findings by OWASP category.
- The **Severity** filter applies inside the groups.

- **Download Test result** (next to the Scan button, shown after a scan)
  downloads a standalone HTML report: embedded CSS, no scripts, works offline,
  printable. It has a summary by test target, a summary by OWASP Top 10 and the
  findings grouped by test target.
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
  cross-site requests). It runs one scan at a time.
- **Binding anywhere other than `127.0.0.1`** (for example `--host 0.0.0.0`)
  needs `--allow-remote` as well, or the server refuses to start. With
  `--allow-remote`, every request needs an access token: a random one is
  generated and printed at startup (or set your own with `--token`), together
  with a ready-to-open URL (`http://host:port/?token=...`). Opening that URL
  once sets a cookie for the rest of the browser session; API calls can also
  send `X-Scanner-Token: <token>`. The token is never written to the server's
  console log, even when it arrives in the URL. Anyone who has the token can
  start scans from this machine, so treat it like a password and prefer the
  default loopback bind unless you really need remote access.
- No extra dependencies: the server uses Python's `http.server`, and the UI is
  static HTML/CSS/JS in `websec_scanner/static/` that loads nothing from the
  internet.

## Development

Run the same steps as CI on your machine:

```bash
pip install -r requirements-dev.txt   # the package in editable mode + ruff, pytest, jsonschema
ruff check . && ruff format --check .
python -m pytest -q                   # offline; talks only to mock servers on 127.0.0.1
```

The test suite covers the acceptance scenarios AT-01 to AT-83 in SRS section 9.
It starts its own HTTP/HTTPS servers on `127.0.0.1` and generates test
certificates (expired, not yet valid, expiring, self-signed), so it needs no
internet access. Tests that need a trusted TLS handshake skip themselves when
local software intercepts TLS.

`benchmarks/` holds an accuracy benchmark that runs the scanner against OWASP Juice Shop
and VAmPI in Docker and fails a change that makes it worse than a recorded baseline. It
is a regression gate, not a detection rate, and runs in CI rather than under `pytest`. See
[benchmarks/README.md](benchmarks/README.md).

**Mock server.** `tests/mock_server.py` serves common misconfigurations
(missing headers, cookie without attributes, exposed `.env` and `.git`,
directory listing, ...) for a quick manual run without scanning a real site:

```bash
python tests/mock_server.py 8899 &
python -m websec_scanner http://127.0.0.1:8899 --yes
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
`main` and `feat/**`, on pull requests to `main`, and (`docker-publish` only)
on version tags (`v*`):

| Job | Status check name(s) | What it does |
|---|---|---|
| `lint` | `lint` | `ruff check .` and `ruff format --check .` |
| `test` | `test (ubuntu-24.04, 3.12)`, `test (ubuntu-24.04, 3.14)`, `test (windows-latest, 3.14)` | Offline `pytest` on Ubuntu 24.04 (Python 3.12, the oldest supported, and 3.14) and Windows (3.14). |
| `min-deps` | `min-deps` | Offline `pytest` on Python 3.12 with the lowest dependency versions `pyproject.toml` allows |
| `audit` | `audit` | `pip-audit` of the runtime dependencies declared in `pyproject.toml` |
| `docker` | `docker` | Builds the official image, checks it runs as a non-root user, and scans `tests/mock_server.py` from inside the container over `--network host` |
| `docker-publish` | *(tag pushes only; not a required check — see below)* | Only on a `v*` tag, after `docker` passes: pushes the same image to `ghcr.io/hkbach/websec-scanner` as `:<tag>` and `:latest`. |
| `secrets` | `secrets` | gitleaks over the whole git history, binary checksum verified. The allowlist in `.gitleaks.toml` covers only two fake values used by the redaction tests. |

The workflow has only `contents: read` permission by default; `docker-publish`
is the one job granted `packages: write`, scoped to that job only, and it is
the only place the workflow uses a secret — `secrets.GITHUB_TOKEN`, the run's
own short-lived token, not one anyone has to create or store. No other job
uses any secret. The `audit`, `secrets` and `docker-publish` jobs need network
access on the runner; the test suite does not.

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
docker
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
     date before merging*, then **Add checks** and add the eight check names
     above (choose the GitHub Actions source if asked).
6. Leave **Bypass list** empty, so the rules also apply to admins.
7. Click **Create**.

### Option B: classic branch protection rule

1. **Settings → Branches → Add classic branch protection rule**.
2. **Branch name pattern:** `main`.
3. Tick **Require a pull request before merging** (set the number of approvals
   as in option A).
4. Tick **Require status checks to pass before merging**, tick **Require
   branches to be up to date before merging**, and search for and add the eight
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
      "lint", "min-deps", "audit", "docker", "secrets",
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
stay disabled until all eight checks pass, and a direct `git push` to `main`
must be rejected.

Rulesets and branch protection are available for public repositories on all
GitHub plans; private repositories need a paid plan.

## Project layout

```text
websec_scanner/
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
  rules/            # sensitive paths and content signatures, known TLS interceptors, TLS probes
  api/              # --api-spec: a safe OpenAPI/Swagger loader and the inventory built from it
  web.py            # local web UI server (python -m websec_scanner.web)
  static/           # index.html, app.js, app.css of the web UI
  checks/
    headers.py         # security headers
    cookies.py         # cookie attributes
    tls_check.py       # TLS and certificate
    tls_probe.py       # which protocol versions and weak ciphers a server accepts
    cors_check.py      # CORS misconfiguration
    exposure.py        # exposed files, directory listing, robots.txt, sitemap.xml
    redirect_check.py  # HTTP to HTTPS redirect
examples/ci/        # CI templates for GitHub Actions, GitLab CI, Azure Pipelines, Jenkins
benchmarks/         # accuracy benchmark against Juice Shop and VAmPI (runs in CI, see its README)
tests/              # offline test suite, mock servers, golden files
docs/               # SRS, JSON Schema of the report
Dockerfile          # official CLI image, non-root, not published to a registry yet
.dockerignore       # keeps the Docker build context to the package itself
THIRD_PARTY_LICENSES.md  # license of every dependency, direct and transitive
```

## Changelog

- **v1.21.0** (API inventory). `--api-spec FILE` lists the servers, endpoints and security schemes
  of an OpenAPI 3.0/3.1 or Swagger 2.0 file. What changes for you:
  - **New option and a new JSON field.** The report gains `api` (an object, or `null` without
    `--api-spec`) and `schema_version` becomes `1.9`. Nothing was removed or renamed, so a
    consumer that ignores unknown fields is unaffected; one that validates against the schema
    needs the new `docs/report.schema.json`.
  - **New runtime dependency: PyYAML** (MIT), used only through its safe loader. Install it
    with the package (`pip install .` pulls it in); the Docker image already has it.
  - **The spec is read, never scanned.** No request goes to any endpoint or server it names,
    and checking the API itself is not part of this release. See "API inventory" above for
    what a spec may not do.
  - The local web UI does not accept a spec (a browser request is limited to 4,096 bytes).

- **v1.20.0** (TLS probing). The TLS check now asks which protocol versions and weak
  cipher suites a server accepts, instead of only reporting the one it negotiated. What
  changes for you:
  - **A server that offers TLS 1.2 and also TLS 1.0 is now reported.** Before, only a
    server that *negotiated* a weak protocol was. `TLS-WEAK-PROTOCOL` (HIGH) now appears
    once per enabled weak version (SSLv3, TLS 1.0, TLS 1.1), and `TLS-WEAK-CIPHER` (HIGH)
    once per enabled weak cipher group (no encryption, export grade, anonymous, RC4,
    3DES, single DES). **A pipeline gated on the default `--fail-on high` can start
    failing for a target that used to pass.** That is the point of the change.
  - **The `instance_key`, and so the fingerprint, of those two findings changes once**:
    from `host:port` to `host:port:<protocol or group>` (for example
    `example.com:443:TLSv1`). A baseline written before v1.20.0 shows them as new; write a
    new one with `--json`. The point is that a baseline can now tell "3DES fixed, RC4
    remains" apart. `schema_version` is unchanged.
  - **Up to 11 more TLS connections per scan** (13 in total with the two certificate
    connections, at most 30 by rule), 0.2 s apart. They go through `--proxy`, count against
    `--rate-limit` and `--max-requests`, and are announced in the consent banner. Turn them
    off with `--no-tls-probe`, `tls_probe = false` in a config file, or the web UI's own
    `--no-tls-probe`.
  - **A probe that cannot run is reported, not skipped**: a line in `errors` says what could
    not be tested and why (unreachable, no reply, not TLS, budget reached).
  - Not probed: SSLv2 (a different hello format that no current server speaks). A server
    that rejects every cipher suite a probe offers is read as not accepting the version, so
    an absent finding is not proof that a version is off.

- **v1.19.0** (web UI). The local web UI no longer accepts credentials in any form.
  What changes for you:
  - `POST /api/scan` now **refuses** a request that carries a credential field
    (`auth`, `password`, `token`, `cookie`, `headers`, `authorization`, `api_key`,
    `show_secrets`, and spellings such as `showSecrets` or `x-api-key`) with HTTP 400,
    `"code": "credential_not_accepted"` and the field's name. Before, such fields were
    silently ignored, so a caller could believe a credential, or `show_secrets`, had been
    honoured. The value is never echoed back or logged.
  - A target with a user name or password in the URL (`https://user:pass@host/`) is
    refused the same way. The CLI still accepts it and masks it in every report.
  - **Any other unknown field is refused too** (`"code": "unknown_field"`). A script that
    posted extra fields to `/api/scan` and relied on them being ignored must stop sending
    them. The page itself is unaffected: it only sends `target`, `authorized` and
    `checks`.
  - Other errors keep their `{"error": ...}` shape; only these refusals add `code` and
    `field`. The scan results, JSON schema and exit codes are unchanged.

- **v1.18.0** (quality audit, part two). The acceptance table and the backlog were
  checked claim by claim against the tests that are supposed to prove them, and the
  core rules were checked by deliberately breaking them. What changes for you:
  - **An excluded target is no longer scanned anyway.** Every request the scanner makes
    honours `--exclude`, `--exclude-host` and the built-in exclusion list — except the
    first fetch of the target itself, which went out regardless. The built-in list is
    exactly the paths where a single GET can log a session out, delete something or
    start a checkout, so pointing a scan at, say, `https://shop.example/checkout/` sent
    the one request those patterns exist to prevent. Such a scan now sends nothing, says
    why in its errors, and exits `3` (incomplete) rather than `0` (clean).
  - No other behaviour changed. The rest of the release is test and documentation work:
    seventeen assertions that an acceptance row claimed but did not check were
    tightened — among them that a missing access token really is refused on the Web UI's
    static files, that the Web UI refuses exactly the targets the CLI refuses, that both
    TLS handshakes go through `--proxy`, and that a report says only once that a scan
    stopped early.
  - Two acceptance rows named the JSON `schema_version` of the sprint that wrote them
    (`1.1` and `1.6`) rather than the current `1.8`; a backlog item delivered in sprint 9
    had never been ticked, and three progress-table cells disagreed with the item list
    they summarise.

- **v1.17.0** (quality audit). A review of the whole system against its specification,
  with no new features. What changes for you:
  - **A target the scanner cannot scan is now refused** with exit code `2` and a clear
    message, before anything is printed or requested. `ftp://host/`, `file:///x`,
    `javascript:...`, `http://` with no host and similar used to be accepted: the scan ran,
    found nothing, and exited `3` with a connection error from inside the HTTP library. The
    local web UI already refused these, so the two now agree.
  - **A scanned site can no longer control your terminal.** Response headers are quoted back
    as evidence, and a site could put terminal escape sequences in them: on a normal
    terminal that let it erase the findings just printed and write its own verdict instead.
    Control characters from a target are now shown as visible `\xNN` text. The scanner's
    own colours are unaffected, and the JSON and SARIF reports keep the real bytes.
  - **A malformed redirect no longer crashes the scan.** `Location: http://evil[.invalid/`
    raised an unhandled error and killed the run; such a redirect is now simply not
    followed, and the report says so.
  - Documentation fixes: the web UI section now lists its options (three were missing since
    v1.14.0), and an acceptance row in the SRS named a test that had been renamed.
  - Three new test files guard these, and a fourth keeps the documentation and the code from
    drifting apart: every option the tools accept must appear in their option tables, and
    every test named by an acceptance row must exist.

- **v1.16.0** (config file, several targets, request options). The JSON report is
  unchanged (`schema_version` 1.8).
  - **`--config scanner.toml`**: every option in one file; the command line wins, and
    repeatable options from both are combined. Unknown keys are errors. `${NAME}` comes
    from the environment, and a credential written into the file gives a warning.
    `--yes` and `--show-secrets` cannot be put in the file.
  - **Several targets**: as arguments, in `--targets-file`, or in the config file. Use
    `--output-dir` (and `--formats`) for one set of reports per target, `--baseline-dir`
    to compare each target with its own previous report, and `--parallel N`. The exit
    code is the worst target's. Credentials are refused when the targets span more than
    one host, since they would reach every target.
  - **Request options**: `--header`, `--cookie`, `--proxy`, `--user-agent`, `--version`,
    `--quiet`, `--verbose`. Credential headers, cookies and the proxy password are masked
    everywhere, even if the target echoes them back and even with `--show-secrets`.
    `--proxy` takes `http://` proxies only and now covers the TLS check too, through a
    `CONNECT` tunnel; it also ignores `NO_PROXY` from the environment. `--user-agent` is
    put in front of the scanner's own User-Agent and never replaces it.

- **v1.15.0** (CI with existing findings). New options, all CLI only:
  - **`--baseline FILE`** fails the gate only on findings that are new since an
    earlier `--json` report, and reports what was fixed. See "Baseline and accepted
    findings" above.
  - **`--suppressions FILE`**: accept known findings in a TOML file, each with a
    mandatory reason and expiry date. (The backlog had planned YAML; TOML is read by
    Python's standard library, so no new dependency, and it allows comments.)
  - **`--csv PATH`** and **`--junit PATH`** exports. CSV cells that would run as a
    spreadsheet formula are defused.
  - **JSON `schema_version` 1.8** (fields added only): a `baseline` block, and on each
    finding `baseline_state` and `suppression` (both `null` when the options are not
    used). `gate` gains `counted` (what the gate actually counted), `basis`, and
    `incomplete_reason`. **`summary` still counts every finding**, as before.
  - **SARIF** uses the standard `baselineState` and `suppressions` properties.
  - **Fingerprint fix (FR-MODEL-07)**: CORS and HTTP-redirect findings used the whole
    start URL, query included, so the same issue got a different fingerprint when the
    scan started on another page or the query carried a rotating token. They now use
    the site root. **Scans that start at the site root keep their fingerprints.** For
    scans that start elsewhere, GitHub code scanning sees these findings as new alerts
    once. A baseline written by an older version triggers a warning to regenerate it.
  - **Fixed:** when a `--max-requests`/`--max-duration` limit stopped a scan, the gate
    message wrongly said the home page could not be fetched (since v1.14.0).

- **v1.14.0** (scan safety controls). Everything here is **off unless you turn it on**, so
  an upgrade changes nothing you have not asked for:
  - **Traffic limits**: `--rate-limit N` (requests per second, applied globally and per
    host), `--max-requests N` and `--max-duration SECONDS`. Reaching a cap stops the scan,
    adds one `Scan stopped early` line to `errors` and marks the report incomplete, so the
    CLI exits 3 — the findings so far are not the whole picture. The scanner also backs off
    on its own when a target answers 429 or 503, honouring `Retry-After` when it is a plain
    number of seconds. The same three options exist on `websec-scanner-web`, where they are
    set when the server starts so a browser user cannot lift them.
  - **JSON `limits` block** (`schema_version` 1.7, fields added only): the limits the scan
    ran under, how many requests it sent, how often it backed off, and which cap stopped it.
  - **Exclusions**: `--exclude REGEX`, `--exclude-host HOST`, and a built-in list in
    `websec_scanner/rules/exclusions.json` covering paths where even a GET can change
    something: logout, delete, checkout, password reset, shutdown. Turn the built-ins off
    with `--no-default-excludes`. Redirects into an excluded path are not followed either.
  - **Declared scope**: `--scope-host HOST` (repeatable) marks extra hosts as in scope.
    Anything else is still refused and reported, as before.
  - **`--scan-id-header`** sends `X-Scanner-Scan-Id` so a target can filter your scan out of
    its own logs and WAF rules.

- **v1.13.0** (CVSS scores revised). A review of the per-type CVSS vectors on 2026-10-01
  corrected several of them, so **scores change for findings you may already have on
  record**:
  - Missing HSTS and "HTTP not redirected to HTTPS" now share one vector (6.8): both
    describe an on-path attacker stripping TLS after the victim navigates over `http://`.
    Expired / not-yet-valid / untrusted certificates drop from 7.4 to 6.8, because the
    victim still has to click past the browser warning.
  - A cookie without `Secure` rises from 3.1 to 5.3; cookies that only lack `HttpOnly` or
    `SameSite` stay at 3.1. Reflected-CORS without credentials drops from 6.5 to 4.3, and a
    weak cipher that still encrypts (RC4/3DES/MD5) scores 5.9 while NULL/EXPORT stays 7.4.
    These are per-finding scores now: the catalog holds the worst case and each check lowers
    it when the evidence is milder.
  - **Findings that are not a scorable weakness no longer carry a score at all**: early
    warnings (certificate expiring soon), hints (robots.txt / sitemap.xml) and everything
    whose severity is INFO. Their `cvss_vector` is `""` and `cvss_score` is `null`.
  - **SARIF `security-severity` is now the CVSS score** instead of a number derived from our
    own severity. **GitHub code scanning will re-rank existing alerts** the first time you
    upload a report from this version.
  - Certificate findings: `TLS-CERT-EXPIRED` and `TLS-CERT-EXPIRING-SOON` are now CWE-324
    (key used past its expiry) rather than the client-side CWE-298.
  - Reports that carry scores now explain, in the console and HTML footer, that CVSS and the
    report's own severity are two different scales.
  - **Weak cipher detection was incomplete and is now a declarative table** (FR-DET-17).
    The old markers were spelled like IANA names but matched against OpenSSL suite names, so
    several suites were never reported: **3DES** (OpenSSL calls it `DES-CBC3-SHA`, which does
    not contain the string `3DES`, so SWEET32 went undetected in practice), single DES
    (`DES-CBC-SHA`), and anonymous suites that authenticate neither side (`ADH-`, `AECDH-`).
    RC2 and IDEA are detected too, and each finding now says *why* the suite is weak. Expect
    new `TLS-WEAK-CIPHER` findings on servers that still offer these.
- **v1.12.0.** Changes to note:
  - **Every finding carries an estimated CVSS v3.1 score** (`cvss_vector`/`cvss_score`,
    schema_version 1.6, fields added only): a generic, per-finding-type estimate (not an
    assessment of your specific target), computed by `websec_scanner/cvss.py` from a
    declarative vector table in `websec_scanner/catalog.py`. Every place that shows it
    labels it "(estimated)"; see the SRS for the `[CONFIRM]` note on reviewing the
    per-type vectors before relying on them commercially.
  - **HTML report**: new "Top issues" section (up to 5 highest-severity findings) in the
    executive summary, and a "Reproduce" line on every finding (re-run with
    `--checks <group>`). Also fixes a leftover "OWASP scan report" page `<title>` from the
    v1.9.0 package rename.
  - **Web UI**: each finding now shows the same estimated CVSS score as the console and
    HTML reports.
- **v1.11.0.** The company name has been removed from the source code entirely (product
  owner, 2026-09-30); it must never appear here. What actually changed:
  - **User-Agent sent to targets (NFR-SEC-03):** the company-name prefix is gone. The
    full current value is `WebSec-Scanner/<version> (+non-intrusive security
    configuration check)`. **If a target's WAF or log filter matches the previous
    value, update it** — this is the second time the User-Agent has changed recently
    (see v1.9.0 above); only this final value is meant to stay.
  - Every other mention of the company name in documentation (README, SRS, backlog,
    the 2026-09-23 review record) was reworded to keep the same technical meaning
    without naming the company.
  - No other behaviour, output field or exit code changed.
- **v1.10.0**. Changes to note:
  - **JSON report has a `disclaimer` field** (schema_version 1.5, fields added only):
    the same scope & limitations text the console and HTML reports already end with
    (`output.SCOPE_NOTE`).
  - **Docker image published to GHCR:** every `v*` release tag builds, smoke-tests and
    pushes `ghcr.io/hkbach/websec-scanner:<tag>` and `:latest` (see "Docker" and
    "Repository CI"). A repository admin still has to set the package's visibility to
    public once.
  - **Web UI title:** the browser tab and page heading now say "WebSec Scanner"
    (matching the CLI banner and User-Agent), not the longer descriptive name used in
    this README/SRS.
- **v1.9.0** (package rename, breaking). The package, PyPI/pip distribution name, CLI
  commands and product identity strings changed from `owasp_scanner`/`owasp-scanner` to
  `websec_scanner`/`websec-scanner`, because the tool is no longer scoped to only OWASP
  checks. What actually changed:
  - **Import path:** `import owasp_scanner` → `import websec_scanner`.
  - **CLI commands:** `owasp-scanner`/`owasp-scanner-web` →
    `websec-scanner`/`websec-scanner-web` (`python -m owasp_scanner` →
    `python -m websec_scanner`, same for `.web`).
  - **PyPI/pip distribution name:** `owasp-scanner` → `websec-scanner`.
  - **User-Agent sent to targets (NFR-SEC-03):** the product-name portion changed to
    `WebSec-Scanner/<version>`; see v1.11.0 below for the full current value.
    **If a target's WAF or log filter matches the old string, it will no longer
    recognise this tool's traffic; update it.**
  - **SARIF `partialFingerprints` key:** `owaspScannerFingerprint/v1` →
    `websecScannerFingerprint/v1`. Existing GitHub code scanning alerts matched on the
    old key lose fingerprint continuity across this release.
  - Downloaded report filenames (`owasp-scan-...` → `websec-scan-...`), the Docker image
    example tag, and product titles in the CLI banner, Web UI and HTML report.
  - **Unchanged:** JSON `schema_version` (1.4), `owasp_category` and `owasp_groups`
    fields (the tool still maps every finding to OWASP Top 10, ASVS and the Secure
    Headers Project — only the tool's own name changed, not what it checks against),
    exit codes, CLI/web behaviour.
- **v1.8.0** (Sprint 9, closing Phase A). Changes to note:
  - **Binding the web UI to anything other than `127.0.0.1` now needs
    `--allow-remote`**, or the server refuses to start (before: it started
    with only a warning). With `--allow-remote`, every request needs an
    access token (`--token`, or a random one printed at startup).
  - Console and HTML reports end with a scope-and-limitations note
    (`output.SCOPE_NOTE`); no format uses absolute-assurance language.
  - New `THIRD_PARTY_LICENSES.md`; a `Dockerfile` (non-root, built and
    smoke-tested in CI, not yet published to a registry); the Jenkins
    template installs from the source archive instead of `git+apt-get`,
    fixing the known non-root failure.
  - Required CI status checks: the new `docker` job joins the required
    list (eight checks now); update branch protection.
  - JSON report and `schema_version` (1.4) are unchanged.
- **v1.7.0** (Sprint 8, test targets):
  - **Choose the test targets of a scan:** `--checks headers,tls,...` and
    `--list-checks` in the CLI, checkboxes on the web page. Unselected test
    targets send no request and are listed as not tested. Without a
    selection every test target runs, as before.
  - **Web UI:** new scan form (target, test targets, authorization) and results
    grouped by test target or by OWASP Top 10, with a status per group.
  - **HTML report:** summaries by test target and by OWASP Top 10, findings
    grouped by test target.
  - **JSON `schema_version` 1.4** (fields added only): `scan_groups` and the
    `check` of each finding. SARIF run properties carry `scan_groups`.
  - Web API: `GET /api/checks`; `POST /api/scan` accepts `checks`; the response
    adds `groups` and `owasp_groups`.
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
    `websec_scanner/rules/*.json`; `rules_version` now looks like
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
  - **New User-Agent:** identifies the scanner and carries its real version
    instead of a generic default (see NFR-SEC-03). Update log or WAF filters
    that rely on the previous, generic User-Agent.
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
  trust-chain validation. Details in section 0 of `docs/SRS-websec-scanner.md`.
- **v1.0.0.** First release.
