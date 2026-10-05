"""Two small ASGI middlewares: a request id and safe response headers, and a limit on the size of a body."""

from __future__ import annotations

import secrets

from .errors import problem_response

_STATIC_HEADERS = ((b"cache-control", b"no-store"), (b"x-content-type-options", b"nosniff"))


def new_request_id() -> str:
    return "req_" + secrets.token_hex(8)


class RequestContext:
    """Gives every request an id of the service's own making (a caller-supplied one could forge log lines)."""

    def __init__(self, app) -> None:
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        request_id = new_request_id()
        scope.setdefault("state", {})["request_id"] = request_id

        async def send_with_headers(message):
            if message["type"] == "http.response.start":
                present = {name.lower() for name, _ in message.get("headers", [])}
                extra = [(n, v) for n, v in _STATIC_HEADERS if n not in present]
                message = {
                    **message,
                    "headers": [*message.get("headers", []), *extra, (b"x-request-id", request_id.encode())],
                }
            await send(message)

        await self.app(scope, receive, send_with_headers)


class BodyLimit:
    """Refuses a request body above ``limit`` bytes with 413 before the application reads it.

    Every request of this API is a small JSON document, so the body is read here (up to the limit) and handed to the
    application whole; a body that declares or turns out to be larger is never passed on.
    """

    def __init__(self, app, limit: int) -> None:
        self.app, self.limit = app, limit

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        request_id = scope.get("state", {}).get("request_id", "req_unknown")

        async def refuse():
            response = problem_response(
                413, "body_too_large", f"The request body is larger than {self.limit} bytes.", request_id
            )
            await response(scope, receive, send)

        declared = dict(scope["headers"]).get(b"content-length")
        if declared is not None and declared.isdigit() and int(declared) > self.limit:
            return await refuse()

        chunks: list[bytes] = []
        size = 0
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            chunk = message.get("body", b"")
            size += len(chunk)
            if size > self.limit:
                return await refuse()
            chunks.append(chunk)
            if not message.get("more_body", False):
                break

        body = b"".join(chunks)
        replayed = False

        async def replay():
            nonlocal replayed
            if not replayed:
                replayed = True
                return {"type": "http.request", "body": body, "more_body": False}
            return await receive()  # after the body: the disconnect, as the application expects

        await self.app(scope, replay, send)
