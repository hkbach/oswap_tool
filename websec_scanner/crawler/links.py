"""Which links a page offers and which URLs the crawler may follow (FR-CRAWL-01).

Pure functions: HTML text in, URLs out. Nothing here touches the network.
"""

from __future__ import annotations

import contextlib
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit, urlunsplit

MAX_LINKS_PER_PAGE = 200  # a page that links to thousands of URLs is read up to this many
MAX_URL_LENGTH = 2000

_DEFAULT_PORTS = {"http": 80, "https": 443}
_LINK_TAGS = ("a", "area")  # forms are FR-CRAWL-05, frames and scripts are not pages to visit


def origin_of(url: str) -> tuple[str, str, int | None]:
    """``(scheme, host, port)`` with a default port written the same way as no port."""
    parts = urlsplit(url)
    scheme = (parts.scheme or "").lower()
    try:
        port = parts.port
    except ValueError:
        port = None
    return scheme, (parts.hostname or "").lower(), port if port != _DEFAULT_PORTS.get(scheme) else None


def normalize(url: str) -> str | None:
    """One spelling per page, or None when ``url`` is not something to follow.

    Not followed: any scheme but http/https, a URL with no host, an impossible port, a URL
    that carries credentials (``user:pass@``), and an over-long URL. The fragment is dropped,
    the host is lower-cased, a default port is left out, and the query is kept as it is.
    """
    if len(url) > MAX_URL_LENGTH:
        return None
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError:
        return None
    scheme = parts.scheme.lower()
    host = parts.hostname
    if scheme not in _DEFAULT_PORTS or not host or parts.username is not None or parts.password is not None:
        return None
    if ":" in host:  # an IPv6 address needs its brackets back
        host = f"[{host}]"
    netloc = host if port in (None, _DEFAULT_PORTS[scheme]) else f"{host}:{port}"
    return urlunsplit((scheme, netloc, parts.path or "/", parts.query, ""))


class _LinkParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.base: str | None = None
        self.hrefs: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        wanted = dict(attrs).get("href")
        if tag == "base" and self.base is None and wanted and wanted.strip():
            self.base = wanted.strip()
        elif tag in _LINK_TAGS and wanted and wanted.strip():
            self.hrefs.append(wanted.strip())


def extract_links(html: str, page_url: str) -> list[str]:
    """Absolute URLs of the ``<a>`` and ``<area>`` links in ``html``, once each, in page order.

    Relative links resolve against ``<base href>`` when the page has one, else against
    ``page_url``. At most ``MAX_LINKS_PER_PAGE`` are returned; a link that cannot be made into
    a URL is skipped, not an error.
    """
    parser = _LinkParser()
    with contextlib.suppress(Exception):  # html.parser can raise on pathological input; what it read before stays
        parser.feed(html)
        parser.close()
    base = page_url
    if parser.base:
        try:
            base = urljoin(page_url, parser.base)
        except ValueError:
            base = page_url
    found: list[str] = []
    seen: set[str] = set()
    for href in parser.hrefs:
        try:
            absolute = urljoin(base, href)
        except ValueError:
            continue
        if absolute in seen:
            continue
        seen.add(absolute)
        found.append(absolute)
        if len(found) >= MAX_LINKS_PER_PAGE:
            break
    return found
