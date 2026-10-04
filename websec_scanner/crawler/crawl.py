"""The crawler (FR-CRAWL-01, FR-CRAWL-04): follow same-origin links from the home page.

It asks for pages the way a visitor's browser would: GET only, through the scan's own
session, so the scope guard, ``--exclude``, the rate limit and ``--max-requests`` all apply.
It never reads an answer body past ``MAX_PAGE_BYTES`` and never follows a redirect itself
without checking where it leads: a redirect is a link like any other.

``crawl()`` returns what it saw (``CrawlResult``) and why it stopped; running the checks on
those pages and merging their findings is run_scan()'s job, so this module stays about
finding pages and nothing else.
"""

from __future__ import annotations

import time
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlsplit
from urllib.robotparser import RobotFileParser

from ..http_utils import excluded, get_limited
from ..limits import ScanLimitReached
from . import links

MAX_PAGE_BYTES = 512 * 1024  # how much of one page is read to look for links
MAX_QUERY_VARIANTS = 5  # distinct query strings followed on one path (a calendar has endless ones)
MAX_DISCOVERED = 5000  # URLs queued in one crawl; more are counted, not queued
ROBOTS_AGENT = "WebSec-Scanner"
_REDIRECTS = (301, 302, 303, 307, 308)
_HTML_TYPES = ("text/html", "application/xhtml+xml")

# stopped_reason values
COMPLETE = "complete"
MAX_DEPTH = "max-depth"
MAX_PAGES = "max-pages"
MAX_DURATION = "max-duration"
SCAN_LIMIT = "scan-limit"
ROBOTS_UNAVAILABLE = "robots-unavailable"


@dataclass(frozen=True)
class CrawlOptions:
    """Limits of one crawl; the defaults keep it small (FR-CRAWL-01)."""

    max_depth: int = 2  # links to follow from the home page: 1 = the pages it links to
    max_pages: int = 50  # pages in all, the home page included
    max_duration: float = 60.0  # seconds of crawling
    respect_robots: bool = True  # FR-CRAWL-04

    def __post_init__(self) -> None:
        if self.max_depth < 0:
            raise ValueError("max_depth must be 0 or more")
        if self.max_pages < 1:
            raise ValueError("max_pages must be 1 or more")
        if self.max_duration <= 0:
            raise ValueError("max_duration must be greater than 0 seconds")


@dataclass
class Page:
    """One answer received during the crawl; the body is not kept."""

    url: str
    status: int
    depth: int
    headers: dict
    set_cookies: list[str]
    html: bool  # the answer was an HTML document

    @property
    def checkable(self) -> bool:
        """True when the page-level checks (headers, cookies) apply: a successful HTML page."""
        return self.html and 200 <= self.status < 400 and self.status not in _REDIRECTS


@dataclass
class CrawlResult:
    options: CrawlOptions
    pages: list[Page] = field(default_factory=list)  # the pages fetched, not counting the home page
    skipped: dict[str, int] = field(default_factory=dict)
    stopped_reason: str = COMPLETE
    limit_message: str = ""  # set when a --max-requests / --max-duration cap of the scan stopped it
    errors: list[str] = field(default_factory=list)

    @property
    def pages_visited(self) -> int:
        return len(self.pages) + 1  # the home page was fetched before the crawl

    def skip(self, reason: str) -> None:
        self.skipped[reason] = self.skipped.get(reason, 0) + 1

    def to_dict(self) -> dict:
        """The report's ``crawl`` object (SRS 6.2): counts and settings, no URLs."""
        return {
            "max_depth": self.options.max_depth,
            "max_pages": self.options.max_pages,
            "max_duration": float(self.options.max_duration),
            "respect_robots": self.options.respect_robots,
            "pages_visited": self.pages_visited,
            "skipped": dict(sorted(self.skipped.items())),
            "stopped_reason": self.stopped_reason,
        }


def crawl(
    session,
    start_url: str,
    start_html: str,
    options: CrawlOptions,
    *,
    clock: Callable[[], float] = time.monotonic,
) -> CrawlResult:
    """Crawl from ``start_url`` (the page the baseline GET ended on), whose HTML is ``start_html``."""
    result = CrawlResult(options)
    home = links.normalize(start_url) or start_url
    origin = links.origin_of(home)
    seen: set[str] = {home}
    variants: dict[str, set[str]] = {}
    queue: deque[tuple[str, int]] = deque()
    discovered = 0
    robots: RobotFileParser | None = None
    robots_loaded = False
    started = clock()

    def consider(raw: str, depth: int) -> None:
        """Queue ``raw`` if it is a page this crawl may visit, else count why not."""
        nonlocal discovered
        url = links.normalize(raw)
        if url is None:
            result.skip("not-followable")
            return
        if url in seen:
            return
        seen.add(url)
        if links.origin_of(url) != origin:
            result.skip("other-origin")
            return
        if depth > options.max_depth:
            result.skip("beyond-depth")
            return
        if excluded(session, url):
            result.skip("excluded")
            return
        parts = urlsplit(url)
        path_key = f"{parts.path}"
        known = variants.setdefault(path_key, set())
        if parts.query not in known and len(known) >= MAX_QUERY_VARIANTS:
            result.skip("query-variants")
            return
        if discovered >= MAX_DISCOVERED:
            result.skip("queue-full")
            return
        known.add(parts.query)
        discovered += 1
        queue.append((url, depth))

    for raw in links.extract_links(start_html, home):
        consider(raw, 1)

    try:
        while queue:
            if clock() - started >= options.max_duration:
                result.stopped_reason = MAX_DURATION
                break
            if result.pages_visited >= options.max_pages:
                result.stopped_reason = MAX_PAGES
                break
            url, depth = queue.popleft()

            if options.respect_robots and not robots_loaded:
                robots_loaded = True
                robots, problem = _read_robots(session, home)
                if problem:
                    result.errors.append(problem)
                    result.stopped_reason = ROBOTS_UNAVAILABLE
                    break
            if robots is not None and not robots.can_fetch(ROBOTS_AGENT, url):
                result.skip("robots-disallowed")
                continue

            response, body, error = get_limited(session, url, max_bytes=MAX_PAGE_BYTES, allow_redirects=False)
            if response is None:
                result.skip("fetch-failed")
                result.errors.append(f"Crawler could not fetch {url}: {error}")
                continue

            is_html = _is_html(response)
            page = Page(
                url=url,
                status=response.status_code,
                depth=depth,
                headers=dict(response.headers),
                set_cookies=response.raw.headers.getlist("Set-Cookie"),
                html=is_html,
            )
            result.pages.append(page)

            if response.status_code in _REDIRECTS:
                location = response.headers.get("Location")
                if location:
                    try:
                        consider(urljoin(url, location), depth)  # a redirect is not one level deeper
                    except ValueError:
                        result.skip("not-followable")
            elif is_html and 200 <= response.status_code < 300:
                text = body.decode(response.encoding or "utf-8", errors="replace")
                for raw in links.extract_links(text, url):
                    consider(raw, depth + 1)
    except ScanLimitReached as exc:
        result.stopped_reason = SCAN_LIMIT
        result.limit_message = str(exc)

    if result.stopped_reason == COMPLETE and result.skipped.get("beyond-depth"):
        result.stopped_reason = MAX_DEPTH
    return result


def _is_html(response) -> bool:
    kind = response.headers.get("Content-Type", "").split(";")[0].strip().lower()
    return kind in _HTML_TYPES


def _read_robots(session, home: str) -> tuple[RobotFileParser | None, str]:
    """``(rules, "")``, ``(None, "")`` when there is no robots.txt, or ``(None, problem)`` when it is unreadable.

    RFC 9309: a 4xx answer means "no rules" (everything allowed); a server error or no answer
    means the rules are unknown, and guessing "allowed" would be the less careful reading.
    """
    robots_url = urljoin(home, "/robots.txt")
    response, body, error = get_limited(session, robots_url, max_bytes=MAX_PAGE_BYTES)
    if response is None:
        return None, (
            f"Could not read {robots_url} ({error}); the crawl stopped. "
            "Use --ignore-robots to crawl without robots.txt."
        )
    if response.status_code >= 500:
        return None, (
            f"{robots_url} answered HTTP {response.status_code}; the crawl stopped because robots.txt "
            "rules are unknown. Use --ignore-robots to crawl without robots.txt."
        )
    if response.status_code >= 400:
        return None, ""
    parser = RobotFileParser()
    parser.parse(body.decode(response.encoding or "utf-8", errors="replace").splitlines())
    return parser, ""
