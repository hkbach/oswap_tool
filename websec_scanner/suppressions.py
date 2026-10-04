"""Accept known findings on purpose: a reason and an end date are required (FR-MODEL-06).

The file is TOML (stdlib ``tomllib``, so no extra dependency), conventionally named
``.scannerignore.toml``::

    # HSTS is added by the CDN in front of the origin we scan.
    [[suppress]]
    id = "HDR-STRICT-TRANSPORT-SECURITY-MISSING"
    reason = "Set at the CDN; tracked in SEC-123"
    expires = 2026-12-31

An entry matches a finding when **every** field it gives matches: ``id``, ``fingerprint``,
and ``path`` (a glob on the URL path, e.g. ``/legacy/*``). A suppressed finding stays in
the report, marked, and simply does not count toward the CI gate. An expired entry stops
suppressing and the report says so.

The loader is strict on purpose: a typo in a key must not quietly turn an entry into one
that matches everything.
"""

from __future__ import annotations

import datetime
import fnmatch
import re
import tomllib
from dataclasses import dataclass
from urllib.parse import urlsplit

_FINGERPRINT = re.compile(r"^[0-9a-f]{32}$")
_MATCH_KEYS = ("id", "fingerprint", "path")
_ALLOWED_KEYS = {*_MATCH_KEYS, "reason", "expires"}


class SuppressionError(ValueError):
    """The suppression file cannot be used; the message says why."""


@dataclass(frozen=True)
class Suppression:
    reason: str
    expires: datetime.date
    id: str | None = None
    fingerprint: str | None = None
    path: str | None = None

    def matches(self, finding: dict) -> bool:
        if self.id is not None and finding.get("id") != self.id:
            return False
        if self.fingerprint is not None and finding.get("fingerprint") != self.fingerprint:
            return False
        if self.path is not None:
            path = urlsplit(finding.get("url") or "").path or "/"
            if not fnmatch.fnmatchcase(path, self.path):
                return False
        return True

    def describe(self) -> str:
        parts = [f"{key}={getattr(self, key)}" for key in _MATCH_KEYS if getattr(self, key) is not None]
        return ", ".join(parts)


@dataclass(frozen=True)
class Suppressions:
    source: str
    active: tuple[Suppression, ...]
    expired: tuple[Suppression, ...]

    def apply(self, report: dict) -> None:
        """Mark matching findings and record each expired entry in ``errors``."""
        for finding in report["findings"]:
            rule = next((s for s in self.active if s.matches(finding)), None)
            finding["suppression"] = (
                None if rule is None else {"reason": rule.reason, "expires": rule.expires.isoformat()}
            )
        for rule in self.expired:
            report["errors"].append(
                f"Suppression ({rule.describe()}) in {self.source} expired on {rule.expires.isoformat()}; "
                "matching findings count toward the gate again (FR-MODEL-06)"
            )


def load_suppressions(path: str, today: datetime.date | None = None) -> Suppressions:
    """Read and validate a suppression file. Raises ``SuppressionError`` with a clear message."""
    today = today or datetime.date.today()
    try:
        with open(path, "rb") as fh:
            data = tomllib.load(fh)
    except OSError as exc:
        raise SuppressionError(f"cannot read suppression file {path!r}: {exc.strerror or exc}") from exc
    except tomllib.TOMLDecodeError as exc:
        raise SuppressionError(f"suppression file {path!r} is not valid TOML: {exc}") from exc

    unknown_top = set(data) - {"suppress"}
    if unknown_top:
        raise SuppressionError(f"{path}: unknown key(s) {sorted(unknown_top)}; entries go under [[suppress]]")
    entries = data.get("suppress", [])
    if not isinstance(entries, list):
        raise SuppressionError(f"{path}: 'suppress' must be an array of tables, written [[suppress]]")

    active, expired = [], []
    for number, entry in enumerate(entries, start=1):
        rule = _parse_entry(path, number, entry)
        (active if rule.expires >= today else expired).append(rule)
    return Suppressions(source=path, active=tuple(active), expired=tuple(expired))


def _parse_entry(path: str, number: int, entry: object) -> Suppression:
    where = f"{path}: suppression #{number}"
    if not isinstance(entry, dict):
        raise SuppressionError(f"{where} is not a table")
    unknown = set(entry) - _ALLOWED_KEYS
    if unknown:
        raise SuppressionError(f"{where} has unknown key(s) {sorted(unknown)}; allowed: {sorted(_ALLOWED_KEYS)}")
    if not any(entry.get(key) for key in _MATCH_KEYS):
        raise SuppressionError(
            f"{where} needs at least one of {', '.join(_MATCH_KEYS)}; without one it would match every finding"
        )

    reason = entry.get("reason")
    if not isinstance(reason, str) or not reason.strip():
        raise SuppressionError(f"{where} needs a non-empty 'reason'")
    expires = _parse_date(entry.get("expires"))
    if expires is None:
        raise SuppressionError(f"{where} needs 'expires' as a date, e.g. expires = 2026-12-31")

    fingerprint = entry.get("fingerprint")
    if fingerprint is not None and (not isinstance(fingerprint, str) or not _FINGERPRINT.match(fingerprint)):
        raise SuppressionError(f"{where}: 'fingerprint' must be the 32-character hex value from a report")
    for key in ("id", "path"):
        if entry.get(key) is not None and not isinstance(entry[key], str):
            raise SuppressionError(f"{where}: '{key}' must be a string")

    return Suppression(
        reason=reason.strip(),
        expires=expires,
        id=entry.get("id"),
        fingerprint=fingerprint,
        path=entry.get("path"),
    )


def _parse_date(value: object) -> datetime.date | None:
    if isinstance(value, datetime.datetime):
        return value.date()
    if isinstance(value, datetime.date):
        return value
    if isinstance(value, str):
        try:
            return datetime.date.fromisoformat(value.strip())
        except ValueError:
            return None
    return None
