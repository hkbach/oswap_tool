"""The HTTP API of the service, version 1 (decision D12).

Built by ``create_app(settings)``. Every route is a plain ``def`` (FastAPI runs it in a worker thread), because the
database is blocking; the scans themselves run in the background (``runner.py``). Authentication is a Bearer
API key made with ``admin.py``; every query
below is filtered by the agency of that key, so an id of another agency is simply "not found".
"""

import base64
import binascii
import hashlib
import json
import logging
from collections.abc import Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Annotated
from urllib.parse import urlsplit, urlunsplit

from fastapi import Depends, FastAPI, Header, Query, Request, Response
from fastapi.responses import HTMLResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from .. import __version__, catalog
from ..cli import _normalize_target
from ..html_report import render_html
from ..models import SCHEMA_VERSION
from ..redact import redact
from . import ids, models, netguard, security, storage
from .config import API_VERSION, Settings
from .db import DuplicateExternalRef, IdempotencyConflict, NotFound, QueueFull, Repository
from .errors import PROBLEM_JSON, ApiError, install_error_handlers
from .middleware import BodyLimit, RequestContext
from .runner import ScanRunner

log = logging.getLogger("websec_scanner.service")

API_DOC_VERSION = "1.1.0"  # the version of this contract; it changes when the contract does
_DESCRIPTION = """
Request web security scans and read their results. The scanner is non-intrusive: it only sends ordinary GET, HEAD and
OPTIONS requests and never sends a payload that exploits anything.

**Authentication.** Send your API key as `Authorization: Bearer wsk_...`. Call the API from your **backend**, never from
a browser: a key in a web page is a key anyone can read. Every key belongs to one agency and sees only that
agency's data.

**Errors.** Every error is a `application/problem+json` document with a stable `code`; branch on `code`, not on
the text.
Nothing you sent is echoed back in an error.

**Ids.** Ids are made by the service: `cli_...` for a client, `scn_...` for a scan. Attach your own reference to a
client with `external_ref`.

**Scans.** `POST /v1/scans` queues a scan and answers `202` at once; poll `GET /v1/scans/{scan_id}` until `status` is
`completed` or `failed`, then read `/report` (JSON, the same report as the command line) or `/report.html`. Send an
`Idempotency-Key` so that a retry after a timeout does not queue a second scan. You confirm, in `attestation`, that you
are authorized to have the target scanned; the service scans public internet addresses only.
"""
_TAGS = [
    {"name": "service", "description": "Health and what a request can ask for."},
    {"name": "clients", "description": "The clients of your agency. Each scan belongs to one client."},
    {"name": "scans", "description": "Request a scan, follow it, and read its report."},
]

bearer_scheme = HTTPBearer(
    auto_error=False, scheme_name="bearerAuth", description="`Authorization: Bearer wsk_<handle>_<secret>`"
)


@dataclass(frozen=True)
class Principal:
    agency_id: str
    key_id: str
    scopes: tuple[str, ...]


def _problems(*statuses: int) -> dict:
    """The documented non-success answers, all of the one Problem shape."""
    descriptions = {
        400: "The request is malformed (for example an unusable cursor).",
        401: "The API key is missing, malformed, unknown, expired or revoked.",
        403: "The API key does not have the scope this call needs.",
        404: "No such record for your agency.",
        409: "The request conflicts with an existing record, or the report is not ready.",
        413: "The request body is too large.",
        422: "The request is not valid; `errors` says where.",
        429: "Too many scans are waiting; retry after the time in `Retry-After`.",
        503: "The service cannot reach its database.",
    }
    return {status: {"model": models.Problem, "description": descriptions[status]} for status in statuses}


def _encode_cursor(value: str) -> str:
    return base64.urlsafe_b64encode(value.encode()).decode().rstrip("=")


def _decode_cursor(cursor: str, kind: str = "client") -> str:
    """The id inside a cursor of this ``kind`` of record, or a 400: a cursor is only ever one the service made."""
    try:
        value = base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4)).decode()
    except (binascii.Error, UnicodeDecodeError, ValueError):
        raise ApiError(400, "invalid_cursor", "The cursor is not one this service gave you.") from None
    if not ids.is_valid(kind, value):
        raise ApiError(400, "invalid_cursor", "The cursor is not one this service gave you.")
    return value


_ERROR_DETAILS = {
    "scan_error": "The scan could not be completed because of a problem inside the service.",
    "interrupted": "The service stopped while the scan was running.",
}


def _scan_view(scan: dict) -> models.Scan:
    """What the API says about a scan: the target is masked like every text that could hold a secret."""
    return models.Scan(
        scan_id=scan["scan_id"],
        client_id=scan["client_id"],
        target=redact(scan["target"]),
        status=scan["status"],
        checks=scan["checks"],
        crawl=scan["crawl"],
        created_at=scan["created_at"],
        started_at=scan["started_at"],
        finished_at=scan["finished_at"],
        summary=models.ScanSummary(**scan["summary"]) if scan["summary"] else None,
        error=(
            models.ScanError(code=scan["error_code"], detail=_ERROR_DETAILS.get(scan["error_code"], "The scan failed."))
            if scan["error_code"]
            else None
        ),
        report_available=scan["status"] == "completed" and bool(scan["result_path"]),
    )


def create_app(
    settings: Settings | None = None,
    repository: Repository | None = None,
    scan_fn: Callable | None = None,
) -> FastAPI:
    settings = settings or Settings.from_env()
    repo = repository or Repository(settings.db_path)
    repo.migrate()
    runner = ScanRunner(settings, repo, scan_fn=scan_fn)
    runner.recover()  # a scan a stopped service left running is failed; what was waiting starts

    @asynccontextmanager
    async def lifespan(_app):
        yield
        runner.close()

    app = FastAPI(
        title="WebSec Scanner Service API",
        version=API_DOC_VERSION,
        description=_DESCRIPTION,
        openapi_tags=_TAGS,
        docs_url=None,  # no interactive page: it would load scripts from a third party
        redoc_url=None,
        openapi_url=f"/{API_VERSION}/openapi.json",
        lifespan=lifespan,
    )
    app.state.settings, app.state.repo, app.state.runner = settings, repo, runner
    app.add_middleware(BodyLimit, limit=settings.max_body_bytes)
    app.add_middleware(RequestContext)  # added last, so it is the outermost: the 413 of BodyLimit has its id too
    install_error_handlers(app)

    def unauthorized() -> ApiError:  # a new one each time: a reused exception would keep every traceback
        return ApiError(
            401, "unauthorized", "Missing, malformed or invalid API key.", headers={"WWW-Authenticate": "Bearer"}
        )

    def authenticate(
        request: Request, credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer_scheme)]
    ) -> Principal:
        if credentials is None:
            raise unauthorized()
        parts = security.split_key(credentials.credentials)
        if parts is None:
            security.verify_secret("-", None)  # about the same work as for a key that is well-formed but wrong
            raise unauthorized()
        handle, secret = parts
        record = repo.find_key(handle)
        valid = security.verify_secret(secret, record["secret_hash"] if record else None)
        # One answer for every reason, so a caller learns nothing about which keys exist.
        if not valid or record is None or record["revoked_at"] or record["agency_status"] != "active":
            raise unauthorized()
        if record["expires_at"] and record["expires_at"] <= repo.now_iso():
            raise unauthorized()
        repo.touch_key(record["key_id"], settings.key_touch_seconds)
        return Principal(record["agency_id"], record["key_id"], tuple(record["scopes"]))

    def require(scope: str):
        def check(principal: Annotated[Principal, Depends(authenticate)]) -> Principal:
            if scope not in principal.scopes:
                raise ApiError(403, "forbidden", f"This API key does not have the scope {scope!r}.")
            return principal

        return check

    def ip_of(request: Request) -> str | None:
        return request.client.host if request.client else None

    # --- service -----------------------------------------------------------------------------------

    @app.get(
        "/healthz",
        tags=["service"],
        operation_id="getHealth",
        summary="Is the service up?",
        response_model=models.Health,
        responses=_problems(503),
    )
    def healthz() -> models.Health:
        """No key needed. Says nothing about the data."""
        if not repo.ping():
            raise ApiError(503, "unavailable", "The database cannot be reached.")
        return models.Health(status="ok", service_version=__version__)

    @app.get(
        f"/{API_VERSION}/options",
        tags=["service"],
        operation_id="getOptions",
        summary="What a scan request can ask for",
        response_model=models.Options,
        responses=_problems(401),
    )
    def get_options(_: Annotated[Principal, Depends(authenticate)]) -> models.Options:
        """The check groups and the limits of a crawl, so your front end can draw the same form as the demo page."""
        crawl = settings.crawl
        return models.Options(
            api_version=API_VERSION,
            scanner_version=__version__,
            report_schema_version=SCHEMA_VERSION,
            check_groups=[
                models.CheckGroup(id=g.id, title=g.title, description=g.description) for g in catalog.CHECK_GROUPS
            ],
            crawl=models.CrawlLimits(
                max_depth=crawl.max_depth,
                max_pages=crawl.max_pages,
                max_duration=crawl.max_duration,
                respect_robots=True,
            ),
        )

    # --- clients -----------------------------------------------------------------------------------

    @app.post(
        f"/{API_VERSION}/clients",
        tags=["clients"],
        operation_id="createClient",
        summary="Create a client",
        status_code=201,
        response_model=models.Client,
        responses=_problems(401, 403, 409, 413, 422),
    )
    def create_client(
        body: models.ClientCreate, request: Request, principal: Annotated[Principal, Depends(require("clients:write"))]
    ) -> dict:
        """Required scope: `clients:write`. `external_ref` is your own reference, unique among your active clients."""
        try:
            return repo.create_client(
                principal.agency_id,
                body.display_name,
                body.external_ref,
                body.metadata,
                key_id=principal.key_id,
                ip=ip_of(request),
            )
        except DuplicateExternalRef:
            raise ApiError(
                409, "external_ref_taken", "One of your active clients already has this external_ref."
            ) from None

    @app.get(
        f"/{API_VERSION}/clients",
        tags=["clients"],
        operation_id="listClients",
        summary="List your clients",
        response_model=models.ClientList,
        responses=_problems(400, 401, 403, 422),
    )
    def list_clients(
        principal: Annotated[Principal, Depends(require("clients:read"))],
        external_ref: Annotated[
            str | None, Query(pattern=models._EXTERNAL_REF, description="Only the client with this reference.")
        ] = None,
        limit: Annotated[
            int, Query(ge=1, le=settings.max_page_size, description="Page size.")
        ] = settings.default_page_size,
        cursor: Annotated[str | None, Query(description="`next_cursor` of the previous page.")] = None,
    ) -> models.ClientList:
        """Required scope: `clients:read`. In order of creation, oldest first, in pages."""
        after = _decode_cursor(cursor, "client") if cursor else None
        rows = repo.list_clients(principal.agency_id, external_ref=external_ref, limit=limit, after=after)
        page = rows[:limit]
        more = len(rows) > limit
        return models.ClientList(
            items=[models.Client(**row) for row in page],
            next_cursor=_encode_cursor(page[-1]["client_id"]) if more else None,
        )

    def own_client_id(client_id: str) -> str:
        """An id that cannot be one is "not found", the same answer as for an id that is not yours."""
        if not ids.is_valid("client", client_id):
            raise ApiError(404, "not_found", "No such client.")
        return client_id

    @app.get(
        f"/{API_VERSION}/clients/{{client_id}}",
        tags=["clients"],
        operation_id="getClient",
        summary="Read a client",
        response_model=models.Client,
        responses=_problems(401, 403, 404),
    )
    def get_client(client_id: str, principal: Annotated[Principal, Depends(require("clients:read"))]) -> dict:
        """Required scope: `clients:read`."""
        try:
            return repo.get_client(principal.agency_id, own_client_id(client_id))
        except NotFound:
            raise ApiError(404, "not_found", "No such client.") from None

    @app.patch(
        f"/{API_VERSION}/clients/{{client_id}}",
        tags=["clients"],
        operation_id="updateClient",
        summary="Change a client's name or labels",
        response_model=models.Client,
        responses=_problems(401, 403, 404, 413, 422),
    )
    def update_client(
        client_id: str,
        body: models.ClientUpdate,
        request: Request,
        principal: Annotated[Principal, Depends(require("clients:write"))],
    ) -> dict:
        """Required scope: `clients:write`. `external_ref` cannot be changed."""
        try:
            return repo.update_client(
                principal.agency_id,
                own_client_id(client_id),
                display_name=body.display_name,
                metadata=body.metadata,
                key_id=principal.key_id,
                ip=ip_of(request),
            )
        except NotFound:
            raise ApiError(404, "not_found", "No such client.") from None

    @app.delete(
        f"/{API_VERSION}/clients/{{client_id}}",
        tags=["clients"],
        operation_id="deleteClient",
        summary="Delete a client",
        status_code=204,
        response_class=Response,
        responses=_problems(401, 403, 404),
    )
    def delete_client(
        client_id: str, request: Request, principal: Annotated[Principal, Depends(require("clients:write"))]
    ) -> Response:
        """Required scope: `clients:write`. The client leaves every read; its `external_ref` can be used again."""
        try:
            repo.delete_client(
                principal.agency_id, own_client_id(client_id), key_id=principal.key_id, ip=ip_of(request)
            )
        except NotFound:
            raise ApiError(404, "not_found", "No such client.") from None
        return Response(status_code=204)

    # --- scans -------------------------------------------------------------------------------------

    def refuse_target(raw: str) -> tuple[str, str]:
        """``(normalised URL, host)`` of a target this service will scan, or the 422 that says why not."""
        if netguard.has_userinfo(raw):  # on what was written: the web UI refuses a credential the same way
            raise ApiError(
                422,
                "credential_not_accepted",
                "The target contains a user name or password; the service never accepts them.",
            )
        try:
            target = _normalize_target(raw.strip())
        except ValueError:
            raise ApiError(
                422, "invalid_target", "The target must be an http:// or https:// URL or a host name."
            ) from None
        parts = urlsplit(target)  # a host name has no case: two spellings of one target are one request
        target = urlunsplit(parts._replace(netloc=parts.netloc.lower()))
        if not settings.allow_private_targets:
            try:
                netguard.check_target(target)
            except netguard.TargetError as exc:
                raise ApiError(422, exc.code, exc.detail) from None
        return target, (urlsplit(target).hostname or "").lower()

    def own_scan_id(scan_id: str) -> str:
        if not ids.is_valid("scan", scan_id):
            raise ApiError(404, "not_found", "No such scan.")
        return scan_id

    @app.post(
        f"/{API_VERSION}/scans",
        tags=["scans"],
        operation_id="createScan",
        summary="Request a scan",
        status_code=202,
        response_model=models.Scan,
        responses={
            202: {
                "description": "The scan is queued. `Location` is its address; `Idempotent-Replayed: true` means "
                "an earlier "
                "request with the same `Idempotency-Key` already queued it.",
                "headers": {
                    "Location": {"schema": {"type": "string"}, "description": "`/v1/scans/{scan_id}`"},
                    "Idempotent-Replayed": {"schema": {"type": "string", "enum": ["true"]}},
                },
            },
            **_problems(401, 403, 404, 409, 413, 422, 429),
        },
    )
    def create_scan(
        body: models.ScanCreate,
        request: Request,
        response: Response,
        principal: Annotated[Principal, Depends(require("scans:write"))],
        idempotency_key: Annotated[
            str | None,
            Header(
                alias="Idempotency-Key",
                pattern=models.IDEMPOTENCY_KEY_PATTERN,
                description="Your own key for this request (1 to 64 of `A-Z a-z 0-9 . _ : -`), kept for 24 hours.",
            ),
        ] = None,
    ) -> models.Scan:
        """Required scope: `scans:write`. Queues the scan and answers at once; the scan runs in the background.

        A repeated `Idempotency-Key` with the same body returns the first scan; with a different body it is a 409.
        Errors that say why a target is refused: `invalid_target`, `credential_not_accepted`, `target_not_allowed`
        (not a public internet address), `target_unresolvable`; and `unsupported_statement_version`, `invalid_checks`.
        """
        if not ids.is_valid("client", body.client_id):
            raise ApiError(404, "not_found", "No such client.")
        if body.attestation.statement_version not in settings.attestation_versions:
            raise ApiError(
                422,
                "unsupported_statement_version",
                f"Supported statement versions: {', '.join(settings.attestation_versions)}.",
            )
        try:
            repo.get_client(
                principal.agency_id, body.client_id
            )  # before any DNS lookup, so a stranger's id costs nothing
        except NotFound:
            raise ApiError(404, "not_found", "No such client.") from None
        try:
            checks = catalog.normalize_groups(body.checks) if body.checks is not None else list(catalog.GROUP_IDS)
        except ValueError:
            raise ApiError(422, "invalid_checks", "Unknown check group id; see GET /v1/options.") from None
        target, host = refuse_target(body.target)
        body_hash = hashlib.sha256(
            json.dumps(
                {
                    "client_id": body.client_id,
                    "target": target,
                    "checks": checks,
                    "crawl": body.crawl,
                    "statement_version": body.attestation.statement_version,
                },
                sort_keys=True,
            ).encode()
        ).hexdigest()
        try:
            scan, replayed = repo.create_scan(
                principal.agency_id,
                body.client_id,
                target=target,
                target_host=host,
                checks=checks,
                crawl=body.crawl,
                statement_version=body.attestation.statement_version,
                idempotency_key=idempotency_key,
                body_hash=body_hash,
                max_queued=settings.max_queued_scans,
                max_queued_per_agency=settings.max_queued_per_agency,
                idempotency_ttl_seconds=settings.idempotency_ttl_seconds,
                key_id=principal.key_id,
                ip=ip_of(request),
            )
        except NotFound:
            raise ApiError(404, "not_found", "No such client.") from None
        except IdempotencyConflict:
            raise ApiError(
                409, "idempotency_key_reused", "This Idempotency-Key was used for a request with a different body."
            ) from None
        except QueueFull:
            raise ApiError(
                429, "queue_full", "Too many scans are waiting; retry later.", headers={"Retry-After": "30"}
            ) from None
        if replayed:
            response.headers["Idempotent-Replayed"] = "true"
        runner.pump()  # a replay may find room for a scan that was waiting; with nothing to start it does nothing
        response.headers["Location"] = f"/{API_VERSION}/scans/{scan['scan_id']}"
        return _scan_view(scan)

    @app.get(
        f"/{API_VERSION}/scans",
        tags=["scans"],
        operation_id="listScans",
        summary="List your scans",
        response_model=models.ScanList,
        responses=_problems(400, 401, 403, 422),
    )
    def list_scans(
        principal: Annotated[Principal, Depends(require("scans:read"))],
        client_id: Annotated[
            str | None, Query(pattern=models.CLIENT_ID_PATTERN, description="Only the scans of this client.")
        ] = None,
        status: Annotated[models.ScanStatus | None, Query(description="Only the scans in this state.")] = None,
        limit: Annotated[
            int, Query(ge=1, le=settings.max_page_size, description="Page size.")
        ] = settings.default_page_size,
        cursor: Annotated[str | None, Query(description="`next_cursor` of the previous page.")] = None,
    ) -> models.ScanList:
        """Required scope: `scans:read`. Newest first, in pages."""
        before = _decode_cursor(cursor, "scan") if cursor else None
        rows = repo.list_scans(principal.agency_id, client_id=client_id, status=status, limit=limit, before=before)
        page = rows[:limit]
        return models.ScanList(
            items=[_scan_view(row) for row in page],
            next_cursor=_encode_cursor(page[-1]["scan_id"]) if len(rows) > limit else None,
        )

    def find_scan(scan_id: str, principal: Principal) -> dict:
        try:
            return repo.get_scan(principal.agency_id, own_scan_id(scan_id))
        except NotFound:
            raise ApiError(404, "not_found", "No such scan.") from None

    @app.get(
        f"/{API_VERSION}/scans/{{scan_id}}",
        tags=["scans"],
        operation_id="getScan",
        summary="Read a scan's state",
        response_model=models.Scan,
        responses=_problems(401, 403, 404),
    )
    def get_scan(scan_id: str, principal: Annotated[Principal, Depends(require("scans:read"))]) -> models.Scan:
        """Required scope: `scans:read`. Poll this until `status` is `completed` or `failed`."""
        return _scan_view(find_scan(scan_id, principal))

    def stored_report(scan: dict) -> bytes:
        if scan["status"] in ("queued", "running"):
            raise ApiError(409, "scan_not_finished", "The scan has not finished; poll GET /v1/scans/{scan_id}.")
        if scan["status"] == "failed":
            raise ApiError(409, "scan_failed", "The scan failed, so there is no report.")
        if not scan["result_path"]:  # completed without a stored result: a fault of the service, not of the caller
            log.error("the completed scan %s has no stored report", scan["scan_id"])
            raise ApiError(500, "internal_error", "The report cannot be read; quote the request_id.")
        try:
            return storage.read_report(settings.results_dir, scan["result_path"])
        except (OSError, storage.StorageError):
            log.error("the report of scan %s cannot be read", scan["scan_id"])
            raise ApiError(500, "internal_error", "The report cannot be read; quote the request_id.") from None

    @app.get(
        f"/{API_VERSION}/scans/{{scan_id}}/report",
        tags=["scans"],
        operation_id="getScanReport",
        summary="Read a scan's report (JSON)",
        response_class=Response,
        responses={
            200: {
                "description": "The report: the same JSON as the command line's `--json` "
                f"(`schema_version` {SCHEMA_VERSION}, described by `docs/report.schema.json`). Secrets are masked.",
                "content": {"application/json": {"schema": {"type": "object", "additionalProperties": True}}},
            },
            **_problems(401, 403, 404, 409),
        },
    )
    def get_report(scan_id: str, principal: Annotated[Principal, Depends(require("scans:read"))]) -> Response:
        """Required scope: `scans:read`. 409 `scan_not_finished` while queued or running, `scan_failed` if it failed."""
        return Response(stored_report(find_scan(scan_id, principal)), media_type="application/json")

    @app.get(
        f"/{API_VERSION}/scans/{{scan_id}}/report.html",
        tags=["scans"],
        operation_id="getScanReportHtml",
        summary="Read a scan's report (HTML)",
        response_class=HTMLResponse,
        responses={
            200: {
                "description": "A standalone HTML page (no scripts, works offline, printable).",
                "content": {"text/html": {}},
            },
            **_problems(401, 403, 404, 409),
        },
    )
    def get_report_html(scan_id: str, principal: Annotated[Principal, Depends(require("scans:read"))]) -> HTMLResponse:
        """Required scope: `scans:read`. The same report as the JSON one, drawn as a page."""
        report = json.loads(stored_report(find_scan(scan_id, principal)))
        return HTMLResponse(
            render_html(report),
            headers={"Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'"},
        )

    # --- the contract ------------------------------------------------------------------------------

    def openapi() -> dict:
        if app.openapi_schema is None:
            schema = FastAPI.openapi(app)
            problem = {"$ref": "#/components/schemas/Problem"}
            for path in schema["paths"].values():
                for operation in path.values():
                    for status, response in operation.get("responses", {}).items():
                        if not status.startswith(("4", "5")):
                            continue
                        # FastAPI adds its own 422 shape where a path or query value is checked; the service answers
                        # every error with a Problem, as application/problem+json (not application/json).
                        response["content"] = {PROBLEM_JSON: {"schema": problem}}
                        if status == "422":
                            response["description"] = _problems(422)[422]["description"]
            for unused in ("HTTPValidationError", "ValidationError"):
                schema["components"]["schemas"].pop(unused, None)
            schema["components"]["securitySchemes"]["bearerAuth"]["bearerFormat"] = "wsk_<handle>_<secret>"
            app.openapi_schema = schema
        return app.openapi_schema

    app.openapi = openapi  # type: ignore[method-assign]
    return app
