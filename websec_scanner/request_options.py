"""Operator-supplied request options: extra headers, cookies, proxy, User-Agent prefix (FR-CI-07).

Everything here comes from the command line or a config file, so it is validated strictly:
a CR/LF in a header value would let one option inject another header (request splitting),
and a credential passed here must be recognised as one so no report can echo it back.
"""

from __future__ import annotations

import re
from urllib.parse import unquote, urlsplit

from .http_utils import USER_AGENT

# RFC 9110 field-name / cookie-name: an HTTP token.
_TOKEN = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")
# A field value may hold visible ASCII, spaces and tabs; nothing that could end the header.
_BAD_VALUE = re.compile(r"[\x00-\x08\x0a-\x1f\x7f]")
# Header names that carry credentials. A value under one of these is treated as a secret and
# masked wherever it shows up in a report. Other values stay as they are: masking "staging"
# everywhere would also mangle every hostname that contains it.
_SENSITIVE_NAMES = frozenset({"authorization", "proxy-authorization", "cookie"})
_SENSITIVE_WORDS = re.compile(r"(token|secret|session|password|passwd|api[-_]?key|auth|credential|signature)", re.I)


def is_sensitive_header(name: str) -> bool:
    return name.lower() in _SENSITIVE_NAMES or bool(_SENSITIVE_WORDS.search(name))


def _check_value(what: str, value: str) -> None:
    if _BAD_VALUE.search(value):
        raise ValueError(f"{what} contains a control character (a line break would inject another header)")


def parse_header(value: str) -> tuple[str, str]:
    """``"Name: value"`` -> ``("Name", "value")``. Raises ValueError."""
    name, sep, rest = value.partition(":")
    name, rest = name.strip(), rest.strip()
    if not sep or not _TOKEN.match(name):
        raise ValueError(f"expected 'Name: value' with a valid header name, got {value!r}")
    _check_value(f"header {name!r}", rest)
    return name, rest


def parse_cookie(value: str) -> tuple[str, str]:
    """``"name=value"`` -> ``("name", "value")``. Raises ValueError."""
    name, sep, rest = value.partition("=")
    name = name.strip()
    if not sep or not _TOKEN.match(name):
        raise ValueError(f"expected 'name=value' with a valid cookie name, got {value!r}")
    _check_value(f"cookie {name!r}", rest)
    if ";" in rest:
        raise ValueError(f"cookie {name!r}: give one cookie per --cookie, without ';'")
    return name, rest


def validate_proxy(value: str) -> str:
    """Accept ``http://[user:pass@]host:port`` only.

    An https:// proxy would need TLS inside TLS for the TLS check's own handshakes, and SOCKS
    needs an extra dependency; both are refused rather than half-supported (FR-CI-11).
    """
    parts = urlsplit(value)
    if parts.scheme.lower() != "http" or not parts.hostname:
        raise ValueError(f"only http:// proxies are supported, e.g. http://proxy.example:3128 (got {value!r})")
    _check_value("proxy URL", value)
    return value


def proxy_credentials(proxy: str | None) -> tuple[str, str] | None:
    """``(user, password)`` from the proxy URL, decoded, or None."""
    if not proxy:
        return None
    parts = urlsplit(proxy)
    if parts.username is None:
        return None
    return unquote(parts.username), unquote(parts.password or "")


def user_agent_prefix(value: str) -> str:
    """Validate a --user-agent prefix and return it stripped. Raises ValueError."""
    _check_value("User-Agent prefix", value)
    if not value.strip():
        raise ValueError("the User-Agent prefix is empty")
    return value.strip()


def user_agent(prefix: str | None) -> str:
    """NFR-SEC-03: a prefix is put in front of the scanner's own User-Agent, never instead of it."""
    if not prefix:
        return USER_AGENT
    _check_value("User-Agent prefix", prefix)
    return f"{prefix.strip()} {USER_AGENT}"


def secrets_of(headers: dict[str, str], cookies: dict[str, str], proxy: str | None) -> list[str]:
    """The values that must never appear in a report: credential headers, every cookie, proxy password."""
    values = [v for k, v in headers.items() if is_sensitive_header(k)]
    for value in list(values):
        # "Bearer <token>": the token alone may be echoed without its scheme.
        scheme, _, token = value.partition(" ")
        if token and scheme.isalpha():
            values.append(token)
    values += list(cookies.values())
    creds = proxy_credentials(proxy)
    if creds and creds[1]:
        values.append(creds[1])
    # Very short values would match by accident and mangle unrelated text.
    return sorted({v for v in values if len(v) >= 4}, key=len, reverse=True)
