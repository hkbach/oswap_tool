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


_TLS_PROBE_FILE = RULES_DIR / "tls_probe.json"
_CIPHER_REASONS = ("no-encryption", "unauthenticated", "broken")
_MAX_CONNECTIONS_CEILING = 100
_CERTIFICATE_CONNECTIONS = 2  # the connection that reads the certificate and the one that checks trust


@dataclass(frozen=True)
class Suite:
    code: int  # IANA value, e.g. 0x0005
    name: str  # IANA name, e.g. TLS_RSA_WITH_RC4_128_SHA


@dataclass(frozen=True)
class ProtocolProbe:
    name: str  # as ssl.SSLSocket.version() spells it: SSLv3, TLSv1, TLSv1.1, TLSv1.2, TLSv1.3
    version: int  # 0x0301 is TLS 1.0
    weak: bool
    probe_suites: tuple[int, ...]  # offered to learn whether the version is enabled


@dataclass(frozen=True)
class CipherGroup:
    id: str
    reason: str  # no-encryption | unauthenticated | broken (FR-DET-17)
    title: str
    description: str  # completes "A cipher suite the server accepts ..."
    markers: tuple[str, ...]  # substrings of the OpenSSL name of a negotiated suite
    suites: tuple[Suite, ...]  # offered by the probe; empty means "recognised, not probed"

    @property
    def probed(self) -> bool:
        return bool(self.suites)


@dataclass(frozen=True)
class TlsProbeRules:
    version: str
    max_connections: int  # for the whole TLS check, certificate connections included
    pause_seconds: float
    probe_timeout_seconds: float
    protocols: tuple[ProtocolProbe, ...]
    groups: tuple[CipherGroup, ...]

    @property
    def probe_count(self) -> int:
        return len(self.protocols) + sum(1 for g in self.groups if g.probed)

    @property
    def connection_count(self) -> int:
        """Connections a full TLS check opens: every probe plus the two certificate connections."""
        return self.probe_count + _CERTIFICATE_CONNECTIONS


def _hex(source: Path, where: str, field: str, value, digits: int = 4) -> int:
    if not isinstance(value, str) or not re.fullmatch(rf"0x[0-9A-Fa-f]{{{digits}}}", value):
        _fail(source, f"{where}: {field} must look like 0x0301 (0x and {digits} hex digits), got {value!r}")
    return int(value, 16)


def _number(source: Path, limits: dict, key: str, low: float, high: float) -> float:
    value = limits.get(key)
    if isinstance(value, bool) or not isinstance(value, int | float) or not low <= value <= high:
        _fail(source, f"limits: {key} must be a number from {low} to {high}")
    return float(value)


def _parse_tls_probe(source: Path) -> TlsProbeRules:
    data = json.loads(source.read_text(encoding="utf-8"))
    version = data.get("version")
    if not isinstance(version, str) or not version.strip():
        _fail(source, "missing or empty 'version'")

    limits = data.get("limits")
    if not isinstance(limits, dict):
        _fail(source, "'limits' must be an object")
    max_connections = limits.get("max_connections")
    if isinstance(max_connections, bool) or not isinstance(max_connections, int):
        _fail(source, "limits: max_connections must be a whole number")
    if max_connections > _MAX_CONNECTIONS_CEILING:
        _fail(source, f"limits: max_connections {max_connections} is above the ceiling of {_MAX_CONNECTIONS_CEILING}")
    pause = _number(source, limits, "pause_seconds", 0, 5)
    probe_timeout = _number(source, limits, "probe_timeout_seconds", 1, 30)

    raw_protocols = data.get("protocols")
    if not isinstance(raw_protocols, list) or not raw_protocols:
        _fail(source, "'protocols' must be a non-empty list")
    protocols: list[ProtocolProbe] = []
    for n, entry in enumerate(raw_protocols, 1):
        name = entry.get("name")
        if not isinstance(name, str) or not name.strip():
            _fail(source, f"protocol {n}: missing or empty 'name'")
        if any(p.name == name for p in protocols):
            _fail(source, f"duplicate protocol {name!r}")
        if not isinstance(entry.get("weak"), bool):
            _fail(source, f"protocol {name}: 'weak' must be true or false")
        suites = entry.get("probe_suites")
        if not isinstance(suites, list) or not suites:
            _fail(source, f"protocol {name}: 'probe_suites' must be a non-empty list")
        codes = tuple(_hex(source, f"protocol {name}", "probe_suites entry", c) for c in suites)
        if len(set(codes)) != len(codes):
            _fail(source, f"protocol {name}: duplicate probe_suites entry")
        protocols.append(
            ProtocolProbe(name, _hex(source, f"protocol {name}", "version", entry.get("version")), entry["weak"], codes)
        )

    raw_groups = data.get("cipher_groups")
    if not isinstance(raw_groups, list) or not raw_groups:
        _fail(source, "'cipher_groups' must be a non-empty list")
    groups: list[CipherGroup] = []
    owner: dict[int, str] = {}
    for n, entry in enumerate(raw_groups, 1):
        group_id = entry.get("id")
        if not isinstance(group_id, str) or not group_id.strip():
            _fail(source, f"cipher group {n}: missing or empty 'id'")
        if any(g.id == group_id for g in groups):
            _fail(source, f"duplicate group {group_id!r}")
        if entry.get("reason") not in _CIPHER_REASONS:
            _fail(source, f"group {group_id}: reason must be one of {', '.join(_CIPHER_REASONS)}")
        for key in ("title", "description"):
            if not isinstance(entry.get(key), str) or not entry[key].strip():
                _fail(source, f"group {group_id}: missing or empty '{key}'")
        markers = entry.get("markers")
        if not isinstance(markers, list) or not markers or not all(isinstance(m, str) and m for m in markers):
            _fail(source, f"group {group_id}: 'markers' must be a non-empty list of strings")
        suites: list[Suite] = []
        for suite in entry.get("suites", []):
            code = _hex(source, f"group {group_id}", "code", suite.get("code"))
            name = suite.get("name")
            if not isinstance(name, str) or not name.startswith("TLS_"):
                _fail(source, f"group {group_id}: suite {code:#06x} needs an IANA 'name' starting with TLS_")
            if code in owner:
                _fail(source, f"suite {code:#06x} is in two groups ({owner[code]} and {group_id})")
            owner[code] = group_id
            suites.append(Suite(code, name))
        groups.append(
            CipherGroup(group_id, entry["reason"], entry["title"], entry["description"], tuple(markers), tuple(suites))
        )

    rules = TlsProbeRules(version.strip(), max_connections, pause, probe_timeout, tuple(protocols), tuple(groups))
    if rules.max_connections < rules.connection_count:
        _fail(
            source,
            f"limits: max_connections {rules.max_connections} does not cover the {rules.probe_count} probes "
            f"plus the {_CERTIFICATE_CONNECTIONS} certificate connections",
        )
    return rules


@functools.cache
def load_tls_probe() -> TlsProbeRules:
    """The protocol versions and weak cipher groups the TLS check probes, and its connection limits."""
    return _parse_tls_probe(_TLS_PROBE_FILE)


def cipher_group_of(cipher_name: str) -> CipherGroup | None:
    """The weak group a negotiated suite belongs to, from its OpenSSL name; None for a sound suite.

    Groups are in order of severity and the first match wins, so EXP-RC2-CBC-MD5 is export grade
    rather than RC2 (FR-DET-17).
    """
    return next((g for g in load_tls_probe().groups if any(marker in cipher_name for marker in g.markers)), None)


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
        f";tls_probe={load_tls_probe().version}"
    )
