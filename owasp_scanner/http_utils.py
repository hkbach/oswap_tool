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

import os
import ssl
from urllib.parse import urljoin, urlsplit

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from . import __version__

DEFAULT_TIMEOUT = 10  # seconds
# NFR-SEC-03: identify the scanner and its version so target logs/WAFs can attribute the traffic.
USER_AGENT = f"TECHVIFY-OWASP-Scanner/{__version__} (+non-intrusive security configuration check)"
MAX_REDIRECTS = 10
# Checks that look at file contents never need more than the first few KiB, and an exposed
# multi-GB dump must not be downloaded (NFR-PERF-02, and it keeps target data off this machine).
MAX_BODY_BYTES = 8192


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


def trust_context(ca_bundle: str | None = None) -> ssl.SSLContext:
    """The one trust decision used by HTTP requests and the TLS check (FR-CI-10, fixes B1).

    ``ca_bundle`` (or ``REQUESTS_CA_BUNDLE`` / ``SSL_CERT_FILE``) *replaces* the default
    store, as in curl and requests. Without one, the operating system's store is used,
    so a CA that the machine trusts (e.g. a corporate or antivirus TLS proxy) is trusted
    by both paths, instead of certifi for one and the OS for the other.
    """
    cafile = ca_bundle or os.environ.get("REQUESTS_CA_BUNDLE") or os.environ.get("SSL_CERT_FILE") or None
    return ssl.create_default_context(cafile=cafile)


class _TrustAdapter(HTTPAdapter):
    """Make requests verify with our SSLContext instead of its certifi-based default.

    Follows requests' documented extension point (build_connection_pool_key_attributes)
    and also stops cert_verify() from pointing the connection at certifi, which urllib3
    would otherwise load *into* the shared context.
    """

    def __init__(self, ssl_context: ssl.SSLContext, **kwargs) -> None:
        self._ssl_context = ssl_context
        super().__init__(**kwargs)

    def build_connection_pool_key_attributes(self, request, verify, cert=None):
        host_params, pool_kwargs = super().build_connection_pool_key_attributes(request, verify, cert)
        if verify is not False:
            pool_kwargs.pop("ca_certs", None)
            pool_kwargs.pop("ca_cert_dir", None)
            pool_kwargs["ssl_context"] = self._ssl_context
        return host_params, pool_kwargs

    def cert_verify(self, conn, url, verify, cert) -> None:
        super().cert_verify(conn, url, verify, cert)
        if verify is not False:
            conn.ca_certs = None
            conn.ca_cert_dir = None


def build_session(
    timeout: int = DEFAULT_TIMEOUT, scope_host: str | None = None, ca_bundle: str | None = None
) -> ScopedSession:
    session = ScopedSession(scope_host)
    session.headers.update({"User-Agent": USER_AGENT})
    session.trust_context = trust_context(ca_bundle)

    retry = Retry(
        total=1,
        connect=1,
        read=1,
        backoff_factor=0.5,
        status_forcelist=(),  # do not retry on 4xx/5xx; that's signal, not noise
        raise_on_status=False,
    )
    adapter = _TrustAdapter(session.trust_context, max_retries=retry)
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


def get_limited(session: requests.Session, url: str, max_bytes: int = MAX_BODY_BYTES, **kwargs):
    """GET that reads at most ``max_bytes`` of the body and then closes the connection.

    Returns ``(response, body_bytes, error_str)``; never raises on network errors.
    """
    try:
        resp = session.get(url, stream=True, **kwargs)
    except requests.exceptions.RequestException as exc:
        return None, b"", str(exc)
    body = b""
    try:
        for chunk in resp.iter_content(chunk_size=4096):
            body += chunk
            if len(body) >= max_bytes:
                break
    except requests.exceptions.RequestException as exc:
        return None, b"", str(exc)
    finally:
        resp.close()
    return resp, body[:max_bytes], None


def decode_body(resp, body: bytes) -> str:
    return body.decode(resp.encoding or "utf-8", errors="replace")
