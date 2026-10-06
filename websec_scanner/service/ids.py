"""Identifiers of the service: a short prefix that says what it is, then a ULID that sorts by creation time.

``cli_01j9z8k2m4q7r5t6v8w0x1y2z3`` is a client, ``ag_...`` an agency, ``scn_...`` a scan, ``key_...`` an API key.
The server makes every id (the agency can attach its own reference to a client, see ``external_ref``), so an id
cannot be chosen to collide with or to look like another agency's.
"""

from __future__ import annotations

import re
import secrets
import time

_ALPHABET = "0123456789abcdefghjkmnpqrstvwxyz"  # Crockford's base 32, lower case: no i, l, o, u
_ULID_LENGTH = 26
_ULID = rf"[0-9a-hjkmnp-tv-z]{{{_ULID_LENGTH}}}"

PREFIXES = {"agency": "ag", "client": "cli", "scan": "scn", "key": "key"}
_PATTERNS = {kind: re.compile(rf"^{prefix}_{_ULID}$") for kind, prefix in PREFIXES.items()}


def new_ulid(now_ms: int | None = None) -> str:
    """26 characters: 48 bits of time in milliseconds, then 80 random bits. Sorts by time."""
    millis = int(time.time() * 1000) if now_ms is None else now_ms
    value = (millis << 80) | secrets.randbits(80)
    chars = []
    for _ in range(_ULID_LENGTH):
        chars.append(_ALPHABET[value & 31])
        value >>= 5
    return "".join(reversed(chars))


def new_id(kind: str, now_ms: int | None = None) -> str:
    return f"{PREFIXES[kind]}_{new_ulid(now_ms)}"


def is_valid(kind: str, value: object) -> bool:
    """True when ``value`` is an id of this kind. Anything else (a string of another kind, bytes, None) is False."""
    return isinstance(value, str) and _PATTERNS[kind].match(value) is not None


def created_ms(value: str) -> int:
    """The creation time in milliseconds since the epoch, read back from an id of any kind."""
    ulid = value.rsplit("_", 1)[1]
    number = 0
    for char in ulid:
        number = (number << 5) | _ALPHABET.index(char)
    return number >> 80
