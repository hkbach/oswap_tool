"""A small multi-page test site for the crawler tests (FR-CRAWL-01/03/04).

``site_handler(pages)`` makes a request handler class for a dict ``path -> Page``; the class
records every request it receives in ``Handler.hits`` so a test can say exactly what the
crawler did and did not ask for. Only paths in the dict exist; anything else is a 404.
"""

from __future__ import annotations

from conftest import QuietHandler


class Page:
    def __init__(self, body="", status=200, content_type="text/html", headers=None, cookies=()):
        self.body = body if isinstance(body, bytes) else body.encode("utf-8")
        self.status = status
        self.content_type = content_type
        self.headers = dict(headers or {})
        self.cookies = list(cookies)


def html(*links: str, extra: str = "") -> str:
    """An HTML page whose body links to ``links`` (hrefs exactly as given)."""
    anchors = "".join(f'<a href="{href}">link</a>\n' for href in links)
    return f"<html><head><title>t</title></head><body>{anchors}{extra}</body></html>"


def site_handler(pages: dict[str, Page]):
    """Handler class serving ``pages``; ``Handler.hits`` lists the request targets in order."""

    class Handler(QuietHandler):
        hits: list[str] = []
        agents: list[str] = []
        methods: list[str] = []

        def do_GET(self):
            type(self).hits.append(self.path)
            type(self).methods.append(self.command)
            type(self).agents.append(self.headers.get("User-Agent", ""))
            page = pages.get(self.path.split("?")[0])
            if page is None:
                self.send(404, b"not found", {"Content-Type": "text/plain"})
                return
            headers = [("Content-Type", page.content_type), *page.headers.items()]
            headers += [("Set-Cookie", cookie) for cookie in page.cookies]
            self.send(page.status, page.body, headers)

        do_HEAD = do_GET

    Handler.hits = []
    Handler.agents = []
    Handler.methods = []
    return Handler
