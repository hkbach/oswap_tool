"""Shared, well-behaved HTTP client for the scanner.

Design goals:
- Never send attack/exploit payloads — only ordinary GET requests.
- Identify itself with a clear User-Agent so target-side logs/WAFs
  can attribute the traffic.
- Bounded timeouts and no retry storms, so the scanner cannot become
  an accidental denial-of-service tool.
- Never follow a redirect to a host outside the scan scope (decision D4):
  the request to that host is simply not sent.
"""

from __future__ import annotations

from urllib.parse import urljoin, urlsplit

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

DEFAULT_TIMEOUT = 10  # seconds
USER_AGENT = "TECHVIFY-OWASP-Scanner/1.0 (+passive security header/config check)"
MAX_REDIRECTS = 10


def _canonical_host(host: str | None) -> str:
    host = (host or "").lower().rstrip(".")
    return host[4:] if host.startswith("www.") else host


def in_scope(url: str, scope_host: str) -> bool:
    """D4: same host as the target, or differing only by a leading ``www.``.

    Scheme and port may change (http -> https, :80 -> :443); other subdomains may not.
    """
    return _canonical_host(urlsplit(url).hostname) == _canonical_host(scope_host)


class ScopedSession(requests.Session):
    """A Session that refuses to follow redirects out of ``scope_host``.

    requests asks ``get_redirect_target()`` where to go next before sending each hop;
    returning None for an out-of-scope location ends the chain there, so the 3xx
    response becomes the final one and nothing is sent to the other host.
    """

    def __init__(self, scope_host: str | None = None) -> None:
        super().__init__()
        self.scope_host = scope_host
        self.max_redirects = MAX_REDIRECTS
        # out-of-scope host -> one error line, so many blocked paths give one report line
        self.blocked_redirects: dict[str, str] = {}

    def get_redirect_target(self, resp):
        location = super().get_redirect_target(resp)
        if location is None or self.scope_host is None:
            return location
        target = urljoin(resp.url, location)
        if in_scope(target, self.scope_host):
            return location
        self.note_blocked(target, resp.url)
        return None

    def note_blocked(self, target: str, from_url: str) -> None:
        """Record one error line per out-of-scope host (also used by checks that follow hops themselves)."""
        host = (urlsplit(target).hostname or target).lower()
        self.blocked_redirects.setdefault(
            host,
            f"Redirect to {host} not followed: outside the scan scope ({self.scope_host}); first seen at {from_url}",
        )


def build_session(timeout: int = DEFAULT_TIMEOUT, scope_host: str | None = None) -> ScopedSession:
    session = ScopedSession(scope_host)
    session.headers.update({"User-Agent": USER_AGENT})

    retry = Retry(
        total=1,
        connect=1,
        read=1,
        backoff_factor=0.5,
        status_forcelist=(),  # do not retry on 4xx/5xx; that's signal, not noise
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    session.request = _with_default_timeout(session.request, timeout)  # type: ignore
    return session


def _with_default_timeout(request_fn, timeout):
    def wrapped(method, url, **kwargs):
        kwargs.setdefault("timeout", timeout)
        return request_fn(method, url, **kwargs)

    return wrapped


def safe_get(session: requests.Session, url: str, **kwargs):
    """GET that never raises on connection issues; returns (response, error_str)."""
    try:
        resp = session.get(url, **kwargs)
        return resp, None
    except requests.exceptions.RequestException as exc:
        return None, str(exc)
