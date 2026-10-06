"""Errors of the API are RFC 9457 problem documents (``application/problem+json``) with a stable ``code``.

Nothing the caller sent is ever echoed back: not in a validation error, not in a 404. A secret that was put in the
wrong field must not come back in a response, a log line or a proxy's cache.
"""

from __future__ import annotations

import logging

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

PROBLEM_JSON = "application/problem+json"
log = logging.getLogger("websec_scanner.service")

_TITLES = {
    400: "Bad request",
    401: "Unauthorized",
    403: "Forbidden",
    404: "Not found",
    405: "Method not allowed",
    409: "Conflict",
    413: "Request too large",
    422: "Validation failed",
    429: "Too many requests",
    500: "Internal error",
    503: "Service unavailable",
}


class ApiError(Exception):
    def __init__(self, status: int, code: str, detail: str, headers: dict[str, str] | None = None) -> None:
        super().__init__(f"{status} {code}: {detail}")
        self.status, self.code, self.detail, self.headers = status, code, detail, headers or {}


def request_id_of(request: Request) -> str:
    return getattr(request.state, "request_id", "req_unknown")


def problem(status: int, code: str, detail: str, request_id: str, errors: list[dict] | None = None) -> dict:
    body = {
        "type": f"urn:websec:problem:{code}",
        "title": _TITLES.get(status, "Error"),
        "status": status,
        "detail": detail,
        "code": code,
        "request_id": request_id,
    }
    if errors is not None:
        body["errors"] = errors
    return body


def problem_response(
    status: int, code: str, detail: str, request_id: str, errors: list[dict] | None = None, headers: dict | None = None
) -> JSONResponse:
    return JSONResponse(
        problem(status, code, detail, request_id, errors), status_code=status, media_type=PROBLEM_JSON, headers=headers
    )


def install_error_handlers(app: FastAPI) -> None:
    @app.exception_handler(ApiError)
    async def _api_error(request: Request, exc: ApiError):
        return problem_response(exc.status, exc.code, exc.detail, request_id_of(request), headers=exc.headers)

    @app.exception_handler(RequestValidationError)
    async def _invalid(request: Request, exc: RequestValidationError):
        # Where and what is wrong, never the value that was sent.
        errors = [
            {"loc": [part for part in e.get("loc", ())], "msg": str(e.get("msg", "")), "type": str(e.get("type", ""))}
            for e in exc.errors()
        ]
        return problem_response(
            422, "validation_error", "The request is not valid; see errors.", request_id_of(request), errors=errors
        )

    @app.exception_handler(StarletteHTTPException)
    async def _http(request: Request, exc: StarletteHTTPException):
        codes = {404: ("not_found", "No such route."), 405: ("method_not_allowed", "That method is not allowed here.")}
        code, detail = codes.get(exc.status_code, ("http_error", "The request could not be served."))
        return problem_response(exc.status_code, code, detail, request_id_of(request), headers=exc.headers)

    @app.exception_handler(Exception)
    async def _unexpected(request: Request, exc: Exception):
        # The request id ties this line to the answer; the exception text can hold anything, so it is not sent.
        log.error("unhandled %s [%s]", type(exc).__name__, request_id_of(request), exc_info=exc)
        # This answer is made by the outermost middleware, outside RequestContext, so it carries its own headers.
        rid = request_id_of(request)
        return problem_response(
            500,
            "internal_error",
            "The service failed to answer; quote the request_id.",
            rid,
            headers={"X-Request-Id": rid, "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"},
        )
