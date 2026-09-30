"""Redaction of secrets in report text (FR-AUTH-02, decision D2).

Three mechanisms, all applied by output.build_report() unless ``--show-secrets``:

* **Exact pairs** declared by a check for its own evidence, e.g. the
  ``name=value`` part of a Set-Cookie header becomes ``name=<redacted len=N>``.
  Replacing only that exact pair (not every occurrence of the value) keeps short
  values such as ``1`` from mangling unrelated text like ``Max-Age=100``.
* **Sensitive query parameters** anywhere in the text (``?token=...``,
  ``&api_key=...``): any parameter whose name contains one of
  ``SENSITIVE_PARAM_WORDS`` has its value masked.
* **Credentials in URLs** (``https://user:password@host``): user and password
  are masked.
"""

from __future__ import annotations

import re
from collections.abc import Iterable

SENSITIVE_PARAM_WORDS = ("token", "key", "session", "sess", "password", "passwd", "pwd", "secret", "sig", "auth", "jwt")

_SENSITIVE_PARAM = re.compile(
    # The value stops at the next parameter, fragment, whitespace, quote or punctuation that
    # usually follows a URL in prose ("url: /x?token=abc, retrying").
    r"([?&;][\w.\-\[\]]*(?:" + "|".join(SENSITIVE_PARAM_WORDS) + r")[\w.\-\[\]]*=)([^&#\s\"'<>,;:)]+)",
    re.IGNORECASE,
)


# Credentials in a URL (``scheme://user:password@host``); user and password are masked separately.
_URL_USERINFO = re.compile(r"(\b[a-zA-Z][a-zA-Z0-9+.\-]*://)([^/?#@\s\"'<>]+)@")


def _mask_userinfo(match: re.Match[str]) -> str:
    user, sep, password = match.group(2).partition(":")
    return f"{match.group(1)}{mask(user)}{sep}{mask(password) if password else ''}@"


def mask(value: str) -> str:
    return f"<redacted len={len(value)}>"


def redact(text: str, pairs: Iterable[tuple[str, str]] = ()) -> str:
    """Apply the exact ``(raw, masked)`` pairs, then mask URL credentials and sensitive URL parameters."""
    for raw, masked in pairs:
        text = text.replace(raw, masked)
    text = _URL_USERINFO.sub(_mask_userinfo, text)
    return _SENSITIVE_PARAM.sub(lambda m: m.group(1) + mask(m.group(2)), text)


def cookie_redaction(set_cookie: str) -> tuple[str, str] | None:
    """The ``(name=value, name=<redacted len=N>)`` pair of one Set-Cookie header, if it has a value."""
    pair = set_cookie.split(";", 1)[0]
    if "=" not in pair:
        return None
    name, value = pair.split("=", 1)
    if not value.strip():
        return None
    return pair, f"{name}={mask(value.strip())}"
