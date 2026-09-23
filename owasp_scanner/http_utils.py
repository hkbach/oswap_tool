"""Shared, well-behaved HTTP client for the scanner.

Design goals:
- Never send attack/exploit payloads — only ordinary GET requests.
- Identify itself with a clear User-Agent so target-side logs/WAFs
  can attribute the traffic.
- Bounded timeouts and no retry storms, so the scanner cannot become
  an accidental denial-of-service tool.
"""
from __future__ import annotations

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

DEFAULT_TIMEOUT = 10  # seconds
USER_AGENT = "TECHVIFY-OWASP-Scanner/1.0 (+passive security header/config check)"


def build_session(timeout: int = DEFAULT_TIMEOUT) -> requests.Session:
    session = requests.Session()
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
