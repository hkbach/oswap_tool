"""The HTTP API of the service, version 1 (decision D12).

Built by ``create_app(settings)``. Every route is a plain ``def`` (FastAPI runs it in a worker thread), because the
database and, later, the scans are blocking. Authentication is a Bearer API key made with ``admin.py``; every query
below is filtered by the agency of that key, so an id of another agency is simply "not found".
"""

import base64
import binascii
import logging
from dataclasses import dataclass
from typing import Annotated

from fastapi import Depends, FastAPI, Query, Request, Response
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from .. import __version__, catalog
from ..models import SCHEMA_VERSION
from . import ids, models, security
from .config import API_VERSION, Settings
from .db import DuplicateExternalRef, NotFound, Repository
from .errors import PROBLEM_JSON, ApiError, install_error_handlers
from .middleware import BodyLimit, RequestContext

log = logging.getLogger("websec_scanner.service")

API_DOC_VERSION = "1.0.0"  # the version of this contract; it changes when the contract does
_DESCRIPTION = """
Request web security scans and read their results. The scanner is non-intrusive: it only sends ordinary GET, HEAD and
OPTIONS requests and never sends a payload that exploits anything.

**Authentication.** Send your API key as `Authorization: Bearer wsk_...`. Call the API from your **backend**, never from
a browser: a key in a web page is a key anyone can read. Every key belongs to one agency and sees only that
agency's data.

**Errors.** Every error is a `application/problem+json` document with a stable `code`; branch on `code`, not on
the text.
Nothing you sent is echoed back in an error.

**Ids.** Ids are made by the service: `cli_...` for a client. Attach your own reference to a client with `external_ref`.
"""
_TAGS = [
    {"name": "service", "description": "Health and what a request can ask for."},
    {"name": "clients", "description": "The clients of your agency. Each scan belongs to one client."},
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
        409: "The request conflicts with an existing record.",
        413: "The request body is too large.",
        422: "The request is not valid; `errors` says where.",
        503: "The service cannot reach its database.",
    }
    return {status: {"model": models.Problem, "description": descriptions[status]} for status in statuses}


def _encode_cursor(client_id: str) -> str:
    return base64.urlsafe_b64encode(client_id.encode()).decode().rstrip("=")


def _decode_cursor(cursor: str) -> str:
    try:
        value = base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4)).decode()
    except (binascii.Error, UnicodeDecodeError, ValueError):
        raise ApiError(400, "invalid_cursor", "The cursor is not one this service gave you.") from None
    if not ids.is_valid("client", value):
        raise ApiError(400, "invalid_cursor", "The cursor is not one this service gave you.")
    return value


def create_app(settings: Settings | None = None, repository: Repository | None = None) -> FastAPI:
    settings = settings or Settings.from_env()
    repo = repository or Repository(settings.db_path)
    repo.migrate()

    app = FastAPI(
        title="WebSec Scanner Service API",
        version=API_DOC_VERSION,
        description=_DESCRIPTION,
        openapi_tags=_TAGS,
        docs_url=None,  # no interactive page: it would load scripts from a third party
        redoc_url=None,
        openapi_url=f"/{API_VERSION}/openapi.json",
    )
    app.state.settings, app.state.repo = settings, repo
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
        after = _decode_cursor(cursor) if cursor else None
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
