# Tutorial: integrating the scanner

This tutorial covers two ways to put the WebSec Scanner into your own systems:

- **[Part A – The agency API](#part-a--the-agency-api).** Your **backend** calls a hosted HTTP API to manage your clients
  and (in a later release) to request scans and read results. Choose this if you sell scans to your own customers and
  want them inside your own web application.
- **[Part B – CI/CD](#part-b--cicd).** A pipeline runs the scanner against a site and fails the build on findings. Choose
  this if you or your customer want a scan on every release or on a schedule.

You can use either one, or both. They run the same scanner.

> This tutorial is for version **1.26.0**. Everything marked **Verified** was run on 2026-10-05 against local test servers
> (a mock site and a local copy of the service); [what was and was not verified](#what-was-and-was-not-verified) is listed
> at the end. Read it before you rely on a part.

## Before you start

- **Authorization.** Scan only systems you own or have written permission to test. The scanner sends only ordinary `GET`,
  `HEAD` and `OPTIONS` requests and TLS handshakes, never an attack payload, but scanning without permission can still be
  illegal or break the owner's terms. In CI, `--yes` means "the approval already exists".
- **What a scan is.** A configuration check, not a full penetration test. A clean report means these checks found nothing;
  it does not mean the site is secure (see "Limitations" in the [README](./README.md)).
- **Load.** One scan of a site sends about 29 requests; `--crawl` adds pages (50 in all by default) and `robots.txt`.
  Rate-limit scans of fragile targets (`--rate-limit`).

---

# Part A – The agency API

## A1. How it fits together

```text
 your customer's browser ──▶  your web app (front end)  ──▶  your backend  ──▶  WebSec service  ──▶  scanner
                                                                  │  Authorization: Bearer wsk_...
                                                                  └─ the key lives only here
```

- **Your backend calls the API, never a browser.** A key placed in a web page is a key anyone can read, and the service
  deliberately sends no cross-origin (CORS) headers. Your front end talks to *your* backend, which talks to the service.
- The service listens on **plain HTTP** (default `127.0.0.1:8780`). It is meant to sit behind a reverse proxy that
  terminates TLS. Never send an API key over a network you do not control without TLS.
- **Every key belongs to one agency** and sees only that agency's data. An id of another agency is answered exactly like an
  id that does not exist.
- The contract is [`docs/openapi.yaml`](./docs/openapi.yaml), also served at `GET /v1/openapi.json`.

## A2. What exists today

| Available now (phase 1) | Not available yet |
|---|---|
| Health check (`GET /healthz`) | The scan endpoints: requesting a scan and reading its result |
| What a scan request can ask for (`GET /v1/options`) | Quotas and rate limits per agency |
| Your clients: create, read, list, change, delete (`/v1/clients`) | Storing, querying and deleting scan results |
| API keys with scopes, expiry and revocation | Webhooks |

**Until the scan endpoints exist, the service cannot scan anything.** You can build and test everything around them now
(authentication, your client records, the form built from `/v1/options`). When the scan endpoints are released the
contract in `docs/openapi.yaml` will be extended and this tutorial updated; the scan request is planned to carry the
fields your demo page already has (target URL, which test targets to run, crawl on/off), but that contract is **not final**
and nothing below depends on it.

## A3. Get access

Keys are made by the operator of the service (TECHVIFY, or you if you host it yourself); there is no public endpoint for it.
You need two things from them: the **base URL** (for example `https://scanner.example.com`) and an **API key**:

```text
wsk_abcd1234_<43 characters>   (an example shape, not a working key)
```

The key is shown **once**, when it is made, and cannot be recovered; only a hash is stored. Put it in your secret store
at once. Ask for one key per system that calls the API, with only the scopes it needs:

| Scope | Allows |
|---|---|
| `clients:read` | `GET /v1/clients`, `GET /v1/clients/{id}` |
| `clients:write` | `POST`, `PATCH` and `DELETE` on clients |
| `scans:read`, `scans:write` | Reserved for the scan endpoints; they do nothing yet |

`GET /v1/options` and `GET /healthz` need no particular scope (`/healthz` needs no key at all).

## A4. Quick start with `curl`   *(Verified)*

```bash
export API=https://scanner.example.com
export KEY=wsk_...        # from your secret store

# 1. Is it up? (no key needed)
curl -s $API/healthz
# {"status":"ok","service_version":"1.26.0"}

# 2. What can a scan request ask for? Draw your form from this.
curl -s -H "Authorization: Bearer $KEY" $API/v1/options
```

`/v1/options` answers with the API version, the scanner version, the report schema version, the eight check groups
(`id`, `title`, `description`, in the order of the demo page) and the limits of a crawl:

```json
{
  "api_version": "v1",
  "scanner_version": "1.26.0",
  "report_schema_version": "1.11",
  "check_groups": [
    {"id": "headers", "title": "Security headers", "description": "HSTS, CSP, ..."},
    {"id": "cookies", "title": "Cookies", "description": "Secure, HttpOnly and SameSite ..."}
  ],
  "crawl": {"max_depth": 2, "max_pages": 50, "max_duration": 60.0, "respect_robots": true}
}
```

```bash
# 3. Create a client of your own. external_ref is YOUR id for it.
curl -s -X POST -H "Authorization: Bearer $KEY" -H "Content-Type: application/json" \
     -d '{"display_name": "Acme Ltd", "external_ref": "acme-1", "metadata": {"plan": "gold"}}' \
     $API/v1/clients
# 201 {"client_id":"cli_01m455a4tdhr1r8h1yf0jyckw0","display_name":"Acme Ltd","external_ref":"acme-1",
#      "metadata":{"plan":"gold"},"created_at":"2026-10-05T04:31:50.093Z","updated_at":"2026-10-05T04:31:50.093Z"}

# 4. Find it again by your own reference
curl -s -H "Authorization: Bearer $KEY" "$API/v1/clients?external_ref=acme-1"
# {"items":[{...}],"next_cursor":null}

# 5. Rename it, then delete it
curl -s -X PATCH -H "Authorization: Bearer $KEY" -H "Content-Type: application/json" \
     -d '{"display_name": "Acme Limited"}' $API/v1/clients/cli_01m455a4tdhr1r8h1yf0jyckw0
curl -s -o /dev/null -w "%{http_code}\n" -X DELETE -H "Authorization: Bearer $KEY" \
     $API/v1/clients/cli_01m455a4tdhr1r8h1yf0jyckw0          # 204
```

## A5. Clients

- **`client_id`** is made by the service: `cli_` plus a 26-character id that sorts by creation time. Keep it, or keep your own
  `external_ref` (1 to 128 characters of `A-Z a-z 0-9 . _ : -`, unique among your *active* clients, fixed once set) and look the
  client up by it.
- **`display_name`**: 1 to 200 characters; surrounding spaces are trimmed.
- **`metadata`**: up to 20 labels. Keys use letters, digits, `_`, `.`, `-` (1 to 64 characters). Values are text (up to 256
  characters), numbers or `true`/`false`; no nesting. **Never put secrets in labels**: keys that look like credentials
  (anything containing `token`, `key`, `password`, `secret`, `session`, `auth`, ...) are rejected with a 422.
- **Unknown fields are an error** (422), so a typo is never silently ignored.
- **Deleting** a client hides it from every read; its `external_ref` can then be used again.
- **Paging.** `GET /v1/clients?limit=100` returns `{"items": [...], "next_cursor": "..."}`. Pass `next_cursor` back as
  `cursor` until it is `null`. `limit` is 1 to 100 (default 50). Pages never repeat or skip a client. A cursor the service did
  not give you is a 400 `invalid_cursor`.

## A6. Errors

Every error is a JSON document of type `application/problem+json` with a stable `code`. **Branch on `code`, not on the text**,
and log the `request_id` (it is also the `X-Request-Id` response header); support will ask for it.

```json
{
  "type": "urn:websec:problem:validation_error",
  "title": "Validation failed",
  "status": 422,
  "detail": "The request is not valid; see errors.",
  "code": "validation_error",
  "request_id": "req_0197e0478d6f975c",
  "errors": [
    {"loc": ["body", "display_name"], "msg": "String should have at least 1 character", "type": "string_too_short"},
    {"loc": ["body", "password"], "msg": "Extra inputs are not permitted", "type": "extra_forbidden"}
  ]
}
```

Nothing you sent is echoed back (`errors` says *where* and *what*, never the value).

| Status | `code` | Meaning | What to do |
|---|---|---|---|
| 400 | `invalid_cursor` | The cursor is not one the service gave you | Start the listing again |
| 401 | `unauthorized` | Key missing, malformed, unknown, wrong, expired, revoked, or your agency is suspended | Check the key. All of these look the same on purpose |
| 403 | `forbidden` | The key lacks the scope this call needs (the text names it) | Ask for a key with that scope |
| 404 | `not_found` | No such record **for your agency** | Includes ids that belong to someone else |
| 405 | `method_not_allowed` | Wrong HTTP method for the route | |
| 409 | `external_ref_taken` | One of your active clients already has this `external_ref` | Look it up instead |
| 413 | `body_too_large` | The request body is over 64 KiB | |
| 422 | `validation_error` | The request is not valid | Read `errors` |
| 500 | `internal_error` | The service failed; no detail is given | Retry later; quote `request_id` |
| 503 | `unavailable` | The service cannot reach its database | Retry later |

**Retrying.** Retry network errors, 500 and 503 with exponential backoff and a limit. `GET`, `PATCH` and `DELETE` are safe to
retry. `POST /v1/clients` has no idempotency key yet: after a timeout, look the client up by `external_ref` before creating it
again (the examples below do this).

## A7. Python client   *(Verified)*

```python
"""A small client for the WebSec Scanner service API (backend use). Needs: pip install requests"""
import os

import requests

BASE_URL = os.environ["WEBSEC_API_URL"]   # e.g. https://scanner.example.com
API_KEY = os.environ["WEBSEC_API_KEY"]    # wsk_..., kept in your secret store, never in code or a web page


class ApiProblem(Exception):
    """An error answer of the service (RFC 9457). Branch on .code, quote .request_id to support."""

    def __init__(self, status, body):
        super().__init__(f"{status} {body.get('code')}: {body.get('detail')} [{body.get('request_id')}]")
        self.status, self.code = status, body.get("code")
        self.request_id, self.errors = body.get("request_id"), body.get("errors")


session = requests.Session()
session.headers["Authorization"] = f"Bearer {API_KEY}"


def call(method, path, **kwargs):
    response = session.request(method, BASE_URL + path, timeout=30, **kwargs)
    if response.status_code == 204:
        return None
    if response.status_code >= 400:
        raise ApiProblem(response.status_code, response.json())
    return response.json()


def find_or_create_client(external_ref, display_name):
    """Your own reference (external_ref) makes this safe to repeat."""
    found = call("GET", "/v1/clients", params={"external_ref": external_ref})["items"]
    if found:
        return found[0]
    try:
        return call("POST", "/v1/clients", json={"display_name": display_name, "external_ref": external_ref})
    except ApiProblem as problem:
        if problem.code == "external_ref_taken":  # another request created it a moment ago
            return call("GET", "/v1/clients", params={"external_ref": external_ref})["items"][0]
        raise


def all_clients():
    """Every client, following next_cursor until it is null."""
    cursor = None
    while True:
        page = call("GET", "/v1/clients", params={"limit": 100, **({"cursor": cursor} if cursor else {})})
        yield from page["items"]
        cursor = page["next_cursor"]
        if cursor is None:
            return
```

## A8. Node.js client   *(Verified, Node 24)*

```javascript
// Needs Node 18+ (global fetch).
const BASE_URL = process.env.WEBSEC_API_URL; // e.g. https://scanner.example.com
const API_KEY = process.env.WEBSEC_API_KEY;  // wsk_..., from your secret store, never in code or a web page

class ApiProblem extends Error {
  constructor(status, body) {
    super(`${status} ${body.code}: ${body.detail} [${body.request_id}]`);
    Object.assign(this, { status, code: body.code, requestId: body.request_id, errors: body.errors });
  }
}

async function call(method, path, { query, json } = {}) {
  const url = new URL(path, BASE_URL);
  for (const [key, value] of Object.entries(query ?? {})) url.searchParams.set(key, value);
  const response = await fetch(url, {
    method,
    headers: { Authorization: `Bearer ${API_KEY}`, ...(json ? { "Content-Type": "application/json" } : {}) },
    body: json ? JSON.stringify(json) : undefined,
    signal: AbortSignal.timeout(30_000),
  });
  if (response.status === 204) return null;
  const body = await response.json();
  if (response.status >= 400) throw new ApiProblem(response.status, body);
  return body;
}

async function* allClients() {
  let cursor;
  do {
    const page = await call("GET", "/v1/clients", { query: { limit: 100, ...(cursor ? { cursor } : {}) } });
    yield* page.items;
    cursor = page.next_cursor;
  } while (cursor);
}
```

## A9. Building your form from `/v1/options`

Your page should look like the demo page: a target URL, the test targets as checkboxes, and a crawl checkbox. Do not hard-code
the list of test targets; draw it from `check_groups` so a new one appears without a release of your front end. The notes
below describe how the demo page behaves, so your pages feel the same:

- All test targets start selected; at least one must stay selected.
- The crawl box is **off by default**. A crawl only adds pages to the `headers` and `cookies` test targets, so disable the
  box (with a short note) while neither of them is selected.
- Show the crawl limits from `options.crawl` next to the box ("up to 50 pages, 2 levels deep, 60 s; robots.txt is
  respected"). They are the operator's limits; a request cannot raise them.
- Require the user to confirm that they are authorized to scan the target, and keep that confirmation on your side: you
  vouch for your clients' authorization, so keep a record of who confirmed what and when.

Your front end sends this to **your backend**, which validates it and calls the service with its key.

## A10. Production checklist

- [ ] The key is in a secret store or environment variable of your backend; it is not in the repository, in a front-end
      bundle, in logs or in error reports.
- [ ] The service is reached over **HTTPS** (through the operator's reverse proxy).
- [ ] Every call has a timeout (the examples use 30 s) and retries only what is safe to retry.
- [ ] Your logs keep the `request_id` of failed calls.
- [ ] You use one key per system, with only the scopes it needs, and an expiry where you can (`--expires-days`).
- [ ] You know how to **rotate** a key: ask the operator for a new one, deploy it, then have the old one revoked. Revoking
      takes effect on the next request.
- [ ] Your code handles `401` (stop and alert: the key was revoked, expired or your agency was suspended) differently from
      `5xx` (retry).
- [ ] You page through lists with `next_cursor` rather than assuming one page.

## A11. For the operator of the service

This is for whoever hosts the service (TECHVIFY or an agency that runs its own).

```bash
pip install "websec-scanner[service]"          # adds FastAPI and uvicorn; the CLI does not need them
export WEBSEC_SERVICE_DATA_DIR=/var/lib/websec-service

python -m websec_scanner.service.admin create-agency "Agency One"                 # prints ag_...
python -m websec_scanner.service.admin create-key ag_... --name backend           # prints the key ONCE
python -m websec_scanner.service.admin create-key ag_... --name reports --scope clients:read --expires-days 90
python -m websec_scanner.service.admin list-keys ag_...                           # never shows secrets
python -m websec_scanner.service.admin revoke-key key_...
python -m websec_scanner.service.admin suspend-agency ag_...                      # all its keys stop working
python -m websec_scanner.service.admin activate-agency ag_...

python -m websec_scanner.service --port 8780                                      # 127.0.0.1 only by default
```

*(Verified: creating an agency and keys, starting the service, and the calls in A4, A7 and A8.)*

- **Settings** are environment variables: `WEBSEC_SERVICE_DATA_DIR` (default `./websec-service-data`, or `--data-dir`),
  and the crawl limits `WEBSEC_SERVICE_CRAWL_DEPTH`, `WEBSEC_SERVICE_CRAWL_MAX_PAGES`, `WEBSEC_SERVICE_CRAWL_MAX_DURATION`
  (defaults 2, 50, 60). A bad value stops the service at start.
- **Data.** The data directory holds one SQLite database (`service.db`) and, later, the scan results (`results/`). Back up the
  whole directory. Keys are stored only as hashes. The database records an audit trail of changes (who, which key, from which
  address), without secrets or client names.
- **TLS.** Put a reverse proxy in front that terminates TLS and forwards to `127.0.0.1:8780`. Bind to another interface only
  if you must (`--host`). *(No proxy configuration was tested for this tutorial.)*
- **Health.** `GET /healthz` returns 200 `{"status":"ok",...}`; use it for a load balancer or uptime check. It reads nothing
  of the data.
- **Upgrades.** The database is migrated at start. A database written by a *newer* version than the service understands
  makes it refuse to start.
- **Not yet in place** (planned for later phases): limits on repeated wrong keys, per-agency quotas and rate limits.
  Until then, put rate limiting on the reverse proxy.

---

# Part B – CI/CD

## B1. What you need

1. **Authorization** to scan the target, recorded where your team keeps such approvals.
2. **A target the runner can reach.** A staging environment is safer than production. Behind a proxy, give
   `--proxy http://host:port` (every request, the TLS handshakes included, goes through it; only `http://` proxies are
   supported).
3. **The scanner installed in the job**, pinned so the scan is reproducible (see B2).
4. **Python 3.12 or newer** on the runner.

## B2. Installing the scanner in a job

```bash
pip install "git+https://github.com/hkbach/oswap_tool@<ref>"
```

`<ref>` is a release tag or a commit. **Use a commit SHA until release tags are published:** at the time of writing the
repository has **no release tags**, so the `v1.26.0` in the templates under [`examples/ci/`](./examples/ci/) does not exist
yet and `pip install` would fail on it. A pinned commit works:

```bash
pip install "git+https://github.com/hkbach/oswap_tool@26efd4411328"     # Verified: pip resolved this commit
```

(Replace it with the commit or tag you were given.) Installing from Git needs `git` on the runner. Where it is not available
(for example a rootless Jenkins agent), install from the tag's source archive instead:
`pip install "https://github.com/hkbach/oswap_tool/archive/refs/tags/<tag>.tar.gz"` (needs a published tag).

> If the repository is not public to your account, give the runner access the way you do for other private dependencies.
> How the scanner is distributed to customers is TECHVIFY's decision; ask them which source to use.

A Docker image can be built from the repository's `Dockerfile` (a non-root image of the CLI). *(Not tested for this
tutorial: no Docker daemon was available. The README's `ghcr.io/hkbach/websec-scanner` tags refer to releases that have
not been published yet.)*

## B3. The scan step   *(Verified)*

```bash
python -m websec_scanner "$TARGET_URL" --yes --no-color --fail-on high \
  --json websec-report.json --sarif websec-report.sarif --html websec-report.html --junit websec-report.xml
```

| Exit code | Meaning | In CI |
|---|---|---|
| `0` | No finding at or above `--fail-on` | Pass |
| `1` | At least one finding at or above `--fail-on` (default: CRITICAL or HIGH) | Fail: read the reports |
| `2` | Authorization not confirmed, or invalid arguments (for example a missing `--yes` in a non-interactive job) | Fail: fix the job |
| `3` | The scan is incomplete: the home page could not be fetched (DNS, network, TLS) | Fail: check the runner's network or the target |

With `--fail-on none` the exit code is always `0`: reports only. If a scan both fails the gate and is incomplete, the code is
`1`. `--fail-on` takes `critical`, `high`, `medium`, `low` or `none`.

`--quiet` prints one line per target, handy in a log:
`http://127.0.0.1:8899/: 12 findings, gate fail (exit 1)`. Keep the reports **even when the step fails** (`if: always()`,
`when: always`, `condition: always()`, `post { always }`), because that is when you need them.

## B4. Platform recipes

The four templates in [`examples/ci/`](./examples/ci/) run the same command; copy the one for your platform and change
`TARGET_URL` and the install line (B2). **None of these pipeline files has been run on the CI systems themselves**; try them
on a non-production target first.

| Platform | Template | Where the reports go |
|---|---|---|
| GitHub Actions | [`github-actions.yml`](./examples/ci/github-actions.yml) | Workflow artifact, and SARIF to code scanning |
| GitLab CI | [`gitlab-ci.yml`](./examples/ci/gitlab-ci.yml) | Job artifacts (30 days) |
| Azure Pipelines | [`azure-pipelines.yml`](./examples/ci/azure-pipelines.yml) | Build artifact `websec-scan-reports` |
| Jenkins | [`Jenkinsfile`](./examples/ci/Jenkinsfile) | Archived artifacts `websec-report.*` |

To show the findings as **test results** in your platform, add the JUnit file (`--junit websec-report.xml`). A finding that
fails the gate becomes a failed test, every other finding a skipped test with the reason, so the dashboard shows failures
exactly when the command exits non-zero. The usual publishing steps (platform syntax, not run here):

```yaml
# GitLab CI: under the job's artifacts
artifacts:
  when: always
  reports:
    junit: websec-report.xml
```

```yaml
# Azure Pipelines: after the scan step
- task: PublishTestResults@2
  condition: always()
  inputs:
    testResultsFormat: JUnit
    testResultsFiles: "$(Build.ArtifactStagingDirectory)/websec-report.xml"
```

```groovy
// Jenkins: in post { always { ... } }
junit allowEmptyResults: true, testResults: 'websec-report.xml'
```

**When to run it.** After a deployment to staging, and on a schedule (the templates run weekly). Avoid running it on every
commit: each run sends requests to a live target.

## B5. Rolling out without breaking the pipeline   *(Verified)*

Do not start by failing builds. Take these steps in order; each command below was run against a test site.

**Step 1 – report only.** See what the scan finds; the job cannot fail:

```bash
python -m websec_scanner "$TARGET_URL" --yes --no-color --fail-on none --json websec-report.json
```

**Step 2 – record a baseline, fail only on what is new.** Save one run's JSON report (commit it, or keep it as a pipeline
artifact), then pass it on every later run:

```bash
# once, on the main branch:
python -m websec_scanner "$TARGET_URL" --yes --fail-on none --json baseline.json
# on every run afterwards:
python -m websec_scanner "$TARGET_URL" --yes --baseline baseline.json --junit websec-report.xml
```

Findings already in the baseline are marked `unchanged` and no longer fail the gate; a **new** finding does (exit `1`). The
report also lists what was fixed. A finding that is missing now is only called *fixed* when its check ran again and the scan
finished; otherwise it is listed as *not rechecked*. Refresh the baseline when you decide the current state is the new normal.
Findings are matched by a stable `fingerprint`, so they survive a different start page or a rotating query token.

**Step 3 – accept known findings on purpose.** Put them in a TOML file with a reason and an expiry date:

```toml
# .scannerignore.toml
[[suppress]]
id = "TLS-NO-HTTPS-REDIRECT"
reason = "HTTPS is added by the load balancer in front of this host (SEC-120)"
expires = 2026-12-31

[[suppress]]
id = "EXPOSURE-ENV"
reason = "Fixture file on the demo host, removed in SEC-123"
expires = 2026-12-31
```

```bash
python -m websec_scanner "$TARGET_URL" --yes --suppressions .scannerignore.toml
```

A suppressed finding still appears in the report, marked, and in the summary counts; it just does not fail the gate. **After
the `expires` date the entry stops applying** and the run says so (`... expired on 2020-01-01; matching findings count toward
the gate again`), so an acceptance cannot silently live forever. An entry matches when every field it gives matches: `id`,
`fingerprint` (from a report), or `path` (a glob on the URL path). The loader is strict: an unknown key, a missing reason or
date, or an entry with nothing to match on rejects the whole file before the scan starts. Use the ids from your own report;
they are the `id` field of each finding.

**Step 4 – enforce.** Keep `--baseline` (or `--suppressions`) and use the default `--fail-on high`, or tighten it to `medium`.

## B6. Crawling in CI   *(Verified)*

By default only the home page is checked for headers and cookies. `--crawl` follows the links of the page on the **same origin**
and checks each HTML page it finds, merging the same issue on many pages into one finding that lists them:

```bash
python -m websec_scanner "$TARGET_URL" --yes --no-color --crawl \
  --crawl-depth 1 --crawl-max-pages 10 --rate-limit 20 --fail-on high --json websec-report.json
```

- It sends only `GET`, follows `robots.txt` (`--ignore-robots` only for a site you own), and never leaves the origin.
- Limits: `--crawl-depth` (default 2), `--crawl-max-pages` (default 50, home page included), `--crawl-max-duration` (default
  60 s). The report says why it stopped (`crawl.stopped_reason`) and lists the pages in `pages`.
- It does **not** run JavaScript, so a single-page application shows few or no links.
- Keep a crawl away from destructive links: the built-in exclusions skip logout, delete and checkout paths; add your own with
  `--exclude REGEX` and `--exclude-host HOST`. `--max-requests N` and `--max-duration SECONDS` cap the whole scan.

## B7. Pages behind a login

Pass a session you already have; the scanner does not log in for you. Keep the value in the platform's secret store:

```bash
python -m websec_scanner "$TARGET_URL" --yes --header "Authorization: Bearer $SCAN_TOKEN" --cookie "session=$SCAN_SESSION"
```

Credential headers, cookie values and a proxy password are masked in every report and log, even if the target echoes them back
and even with `--show-secrets`. They are refused when the targets span several hosts, because they would reach every one.
Use a **test account with the least access** that can see what you want checked, never an administrator's.

## B8. A config file

For many options or many targets, keep them in one file; the command line overrides it:

```toml
# scanner.toml
targets = ["https://staging.example.com/"]
fail_on = "critical"
checks = ["headers", "cookies", "exposed-files"]
rate_limit = 10
crawl = true
crawl_max_pages = 5
output_dir = "reports"
formats = ["json", "junit"]
```

```bash
python -m websec_scanner --config scanner.toml --yes --no-color     # Verified
```

`--yes` and `--show-secrets` cannot be put in the file: a committed file must not turn one run's authorization into a
permanent one. `${NAME}` is replaced from the environment, and a missing variable is an error. With `output_dir`, each target
gets its own files, named after the target; `--baseline-dir` compares each target with its own earlier report.

## B9. Reading the results

- **`websec-report.json`** is the complete report (`schema_version` 1.11, described by
  [`docs/report.schema.json`](./docs/report.schema.json)). Useful fields: `gate` (`failed`, `incomplete`, `counted`),
  `summary` (counts per severity), `findings[]` (`id`, `severity`, `title`, `url`, `evidence`, `recommendation`, `cwe`,
  `confidence`, `fingerprint`, and `affected_urls` with `affected_count` after a crawl), `pages[]`, `crawl`, `limits` (requests
  sent and whether a cap stopped the scan) and `errors`.
- **`websec-report.html`** is a standalone page for people (no scripts, works offline, printable).
- **`websec-report.sarif`** is SARIF 2.1.0 for code-scanning dashboards (GitHub's `upload-sarif` action, as in the template).
- **`websec-report.xml`** is JUnit for test dashboards.
- **Severity is not certainty.** Each finding has a `confidence`; hints from `robots.txt` and `sitemap.xml` are low-confidence.
  Fix or suppress with a reason; do not delete the finding from the report.

## B10. Troubleshooting

| Symptom | Likely cause and what to do |
|---|---|
| Exit `2` right away | A non-interactive job needs `--yes`; or an option is invalid (the message says which) |
| Exit `3`, "Could not fetch ..." | The runner cannot reach the target (DNS, firewall, proxy, timeout). Try `curl -I $TARGET_URL` from the runner; raise `--timeout` for a slow target |
| TLS or certificate errors on an internal site | The target uses a private CA: add `--ca-bundle path/to/ca.pem` (it replaces the trust store for both the HTTP and the TLS check) |
| TLS results describe the wrong certificate | Software on the runner re-signs TLS (a proxy or antivirus); the report warns when the issuer is a known interceptor |
| Behind a corporate proxy | `--proxy http://host:port` (`http://` only). Without it the HTTP requests honour `HTTP_PROXY`/`HTTPS_PROXY`, but the TLS check connects directly |
| Many `429`/`503` answers, or the scan is cut short | The target is rate-limiting you: lower `--rate-limit`; `limits.slowdowns` in the JSON counts how often the scanner backed off. A WAF may also block it: ask the owner to allow the runner |
| The target's logs show odd TLS handshakes | The TLS probes ask for old protocol versions on purpose (about 11 extra handshakes, never completed). Turn them off with `--no-tls-probe` |
| `pip install` fails on `@v1.26.0` | There is no such tag yet; use a commit (B2) |
| A finding you accept keeps failing the build | Add a suppression with a reason and an expiry date (B5), or record a baseline |
| The job takes too long | A crawl adds time: lower `--crawl-max-pages`, or set `--max-duration`. Run it on a schedule, not on every commit |

## B11. Security and data handling in CI

- **Reports describe your target** (URLs, headers, configuration), even though secrets are masked. Keep artifacts only as
  long as you need them (the GitLab template uses 30 days) and share them only with people allowed to see them.
- **Never add `--show-secrets` in CI.**
- **Do not put credentials in the pipeline file.** Use the platform's secret store and pass them as environment variables.
- **Scan only what you are authorized to scan.** A pipeline variable is the wrong place to learn that a target was not approved.

---

# Reference

## Command cheat sheet

| I want to... | Command |
|---|---|
| Scan and fail on HIGH or CRITICAL | `python -m websec_scanner URL --yes --fail-on high` |
| See results without failing | `... --fail-on none` |
| Write all report formats | `... --json r.json --sarif r.sarif --html r.html --junit r.xml --csv r.csv` |
| Fail only on new findings | `... --baseline baseline.json` |
| Accept known findings | `... --suppressions .scannerignore.toml` |
| Check only some test targets | `... --checks headers,cookies` (list them with `--list-checks`) |
| Crawl, politely | `... --crawl --crawl-max-pages 20 --rate-limit 10` |
| Cap a scan | `... --max-requests 200 --max-duration 120` |
| Use a private CA | `... --ca-bundle ca.pem` |
| Use a proxy | `... --proxy http://host:3128` |
| Keep options in a file | `python -m websec_scanner --config scanner.toml --yes` |
| One-line summary per target | `... --quiet` |
| Log every request | `... --verbose` (to stderr; credentials masked) |

## What was and was not verified

| Part | Status |
|---|---|
| Service: create agency and keys, start it, `healthz`, `options`, create/list/find/rename/delete clients, the error answers shown (409, 422, 401, 403, 404), the Python and Node clients | **Run** on 2026-10-05 against a local copy of the service on loopback, with Python 3.14 and Node 24 |
| CLI: the scan step and its reports, exit codes 0, 1, 2 and 3, `--baseline`, `--suppressions` (including an expired one), `--crawl` with limits, `--config`, `--quiet` | **Run** against the repository's local mock site, not a real target |
| Installing from a pinned commit with `pip` | **Run** (`--dry-run`) |
| The four pipeline templates, the JUnit publishing snippets | **Not run** on GitHub, GitLab, Azure or Jenkins |
| Docker image, GHCR tags | **Not tested**; no Docker daemon was available, and no release tag has been published |
| Reverse proxy and TLS in front of the service, running the service for real traffic or load | **Not tested** |
| The scan endpoints of the API | **Do not exist yet** |
