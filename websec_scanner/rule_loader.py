"""Load and validate the declarative check tables in ``websec_scanner/rules/`` (NFR-MAINT-02, FR-EXP-01).

Rules are plain JSON (no extra dependency). Each file carries a ``version``; the
scan report's ``rules_version`` comes from here, so a report says which rule set
produced it.
"""

from __future__ import annotations

import functools
import json
import re
from dataclasses import dataclass
from pathlib import Path

from .models import Severity

RULES_DIR = Path(__file__).with_name("rules")
_SENSITIVE_PATHS_FILE = RULES_DIR / "sensitive_paths.json"
_REQUIRED_PATH_FIELDS = ("path", "id", "severity", "title")


_HTML_START = (b"<!doctype html", b"<html")


def looks_like_html(body: bytes) -> bool:
    return body.lstrip()[:32].lower().startswith(_HTML_START)


@dataclass(frozen=True)
class Signature:
    """What the content of an exposed file looks like (FR-DET-01)."""

    description: str
    pattern: re.Pattern | None = None  # searched in the decoded text
    magic: bytes = b""  # required prefix of the raw bytes
    allow_html: bool = False  # most files are never HTML; an HTML body is a generic page

    def matches(self, body: bytes) -> bool:
        if not body or (not self.allow_html and looks_like_html(body)):
            return False
        if self.magic and not body.startswith(self.magic):
            return False
        return self.pattern is None or self.pattern.search(body.decode("utf-8", errors="replace")) is not None


@dataclass(frozen=True)
class SensitivePath:
    path: str
    id: str
    severity: Severity
    title: str
    signature: Signature


@dataclass(frozen=True)
class SensitivePathRules:
    version: str
    paths: tuple[SensitivePath, ...]


def _fail(source: Path, message: str) -> None:
    raise ValueError(f"{source.name}: {message}")


def _parse_signature(source: Path, n: int, raw) -> Signature:
    if not isinstance(raw, dict):
        _fail(source, f"entry {n}: missing 'signature' (every path needs a content signature, FR-DET-01)")
    description = raw.get("description")
    if not isinstance(description, str) or not description.strip():
        _fail(source, f"entry {n}: signature needs a 'description'")
    regex, magic_hex = raw.get("regex"), raw.get("magic_hex")
    if not regex and not magic_hex:
        _fail(source, f"entry {n}: signature needs a regex or magic_hex")
    pattern = None
    if regex:
        try:
            pattern = re.compile(regex)
        except re.error as exc:
            _fail(source, f"entry {n}: invalid signature regex: {exc}")
    magic = b""
    if magic_hex:
        try:
            magic = bytes.fromhex(magic_hex)
        except ValueError:
            _fail(source, f"entry {n}: invalid signature magic_hex {magic_hex!r}")
    return Signature(description.strip(), pattern, magic, bool(raw.get("allow_html", False)))


def _parse_sensitive_paths(source: Path) -> SensitivePathRules:
    data = json.loads(source.read_text(encoding="utf-8"))
    version = data.get("version")
    if not isinstance(version, str) or not version.strip():
        _fail(source, "missing or empty 'version'")
    entries = data.get("paths")
    if not isinstance(entries, list) or not entries:
        _fail(source, "'paths' must be a non-empty list")

    paths: list[SensitivePath] = []
    seen_ids: set[str] = set()
    seen_paths: set[str] = set()
    for n, entry in enumerate(entries, 1):
        for key in _REQUIRED_PATH_FIELDS:
            if not isinstance(entry.get(key), str) or not entry[key].strip():
                _fail(source, f"entry {n}: missing or empty '{key}'")
        path, finding_id = entry["path"], entry["id"]
        if path.startswith("/") or "://" in path:
            _fail(source, f"entry {n}: path {path!r} must be relative to the target")
        if entry["severity"] not in Severity.__members__:
            _fail(source, f"entry {n}: unknown severity {entry['severity']!r}")
        if finding_id in seen_ids:
            _fail(source, f"entry {n}: duplicate id {finding_id!r}")
        if path in seen_paths:
            _fail(source, f"entry {n}: duplicate path {path!r}")
        seen_ids.add(finding_id)
        seen_paths.add(path)
        signature = _parse_signature(source, n, entry.get("signature"))
        paths.append(SensitivePath(path, finding_id, Severity[entry["severity"]], entry["title"], signature))
    return SensitivePathRules(version.strip(), tuple(paths))


@functools.cache
def _load_cached(source: Path) -> SensitivePathRules:
    return _parse_sensitive_paths(source)


def load_sensitive_paths(source: Path | None = None) -> SensitivePathRules:
    """The sensitive-path table; the bundled file unless ``source`` is given."""
    return _load_cached(source or _SENSITIVE_PATHS_FILE)


_TLS_INTERCEPTORS_FILE = RULES_DIR / "tls_interceptors.json"


@dataclass(frozen=True)
class TlsInterceptorRules:
    version: str
    issuer_keywords: tuple[str, ...]  # lower-case substrings of issuer names


@functools.cache
def load_tls_interceptors() -> TlsInterceptorRules:
    source = _TLS_INTERCEPTORS_FILE
    data = json.loads(source.read_text(encoding="utf-8"))
    version = data.get("version")
    if not isinstance(version, str) or not version.strip():
        _fail(source, "missing or empty 'version'")
    keywords = data.get("issuer_keywords")
    if not isinstance(keywords, list) or not keywords or not all(isinstance(k, str) and k.strip() for k in keywords):
        _fail(source, "'issuer_keywords' must be a non-empty list of strings")
    return TlsInterceptorRules(version.strip(), tuple(k.strip().lower() for k in keywords))


_EXCLUSIONS_FILE = RULES_DIR / "exclusions.json"


@dataclass(frozen=True)
class ExclusionRules:
    version: str
    patterns: tuple[re.Pattern, ...]  # case-insensitive, matched against the URL path


@functools.cache
def load_exclusions() -> ExclusionRules:
    """Paths that are never requested by default: a GET there can still change state (FR-AUTHZ-06)."""
    source = _EXCLUSIONS_FILE
    data = json.loads(source.read_text(encoding="utf-8"))
    version = data.get("version")
    if not isinstance(version, str) or not version.strip():
        _fail(source, "missing or empty 'version'")
    patterns = data.get("patterns")
    if not isinstance(patterns, list) or not patterns or not all(isinstance(p, str) and p.strip() for p in patterns):
        _fail(source, "'patterns' must be a non-empty list of strings")
    compiled = []
    for pattern in patterns:
        try:
            compiled.append(re.compile(pattern, re.IGNORECASE))
        except re.error as exc:
            _fail(source, f"invalid regular expression {pattern!r}: {exc}")
    return ExclusionRules(version.strip(), tuple(compiled))


def is_interceptor_issuer(issuer: str) -> bool:
    """True if a certificate issuer name belongs to known TLS-intercepting software (FR-DET-16)."""
    issuer = issuer.lower()
    return any(keyword in issuer for keyword in load_tls_interceptors().issuer_keywords)


def rules_version() -> str:
    """Version of the bundled rule set, reported as ``rules_version`` (one part per rules file)."""
    return (
        f"sensitive_paths={load_sensitive_paths().version}"
        f";tls_interceptors={load_tls_interceptors().version}"
        f";exclusions={load_exclusions().version}"
    )
