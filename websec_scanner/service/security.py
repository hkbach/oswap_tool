"""API keys of the service (decision D12).

A key looks like ``wsk_<8 characters>_<43 characters>``. The first part names the key (it is the lookup handle and
is not secret), the second is the secret. Only a SHA-256 of the secret is stored: the secret is high entropy and
random, so a plain hash is enough (a slow password hash would only add cost to every request), and it is compared
in constant time. The full key is shown once, when it is made, and appears nowhere else.
"""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets
from dataclasses import dataclass

KEY_PREFIX = "wsk"
SCOPES = ("clients:read", "clients:write", "scans:read", "scans:write")
_HANDLE = re.compile(r"^[a-z0-9]{8}$")
_KEY = re.compile(r"^wsk_([a-z0-9]{8})_([A-Za-z0-9_-]{43})$")
# What a lookup of an unknown key is compared against, so that "no such key" and "wrong secret" take the same time.
_DECOY_HASH = hashlib.sha256(b"websec-service-decoy").hexdigest()


@dataclass(frozen=True)
class NewKey:
    handle: str  # the part of the key that names it
    secret_hash: str
    full: str  # shown once


def hash_secret(secret: str) -> str:
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()


def generate_key() -> NewKey:
    handle = "".join(secrets.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(8))
    secret = secrets.token_urlsafe(32)  # 43 URL-safe characters
    return NewKey(handle=handle, secret_hash=hash_secret(secret), full=f"{KEY_PREFIX}_{handle}_{secret}")


def split_key(token: str) -> tuple[str, str] | None:
    """``(handle, secret)`` of a well-formed key, else None."""
    match = _KEY.match(token)
    return (match.group(1), match.group(2)) if match else None


def verify_secret(secret: str, stored_hash: str | None) -> bool:
    """Constant-time check of ``secret`` against the stored hash; a missing hash is compared with a decoy and fails."""
    expected = stored_hash if stored_hash is not None else _DECOY_HASH
    matches = hmac.compare_digest(hash_secret(secret), expected)
    return matches and stored_hash is not None


def is_handle(value: object) -> bool:
    return isinstance(value, str) and _HANDLE.match(value) is not None


def parse_scopes(values: list[str]) -> list[str]:
    """The scopes asked for, in the order of ``SCOPES``; ValueError names an unknown one."""
    unknown = sorted(set(values) - set(SCOPES))
    if unknown:
        raise ValueError(f"unknown scope {unknown[0]!r}; known scopes: {', '.join(SCOPES)}")
    return [scope for scope in SCOPES if scope in values]
