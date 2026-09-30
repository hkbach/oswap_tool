"""Soft-404 detection by content fingerprint (FR-DET-02).

Some sites answer 200 for any path: a SPA shell, a custom "not found" page, or a
redirect to /login. Content signatures (FR-DET-01) already reject most of those,
but a generic page can still happen to contain a signature ("Contact:", "Index of /").
Two probes to random, certainly-missing paths record what "missing" looks like on
this site; a response that looks the same is treated as missing too.
"""

from __future__ import annotations

import re
import secrets
from dataclasses import dataclass
from difflib import SequenceMatcher
from urllib.parse import urljoin, urlsplit

from .http_utils import get_limited

SIMILARITY_THRESHOLD = 0.9
_COMPARED_CHARS = 4096
_WHITESPACE = re.compile(r"\s+")


def normalize(body: bytes, requested_path: str) -> str:
    """Comparable text: decoded, without the requested path (pages often echo it), whitespace-collapsed."""
    text = body[:_COMPARED_CHARS].decode("utf-8", errors="replace")
    variants = {requested_path, requested_path.rstrip("/"), "/" + requested_path.lstrip("/")}
    for variant in sorted(variants, key=len, reverse=True):  # longest first
        if variant.strip("/"):
            text = text.replace(variant, "")
    return _WHITESPACE.sub(" ", text).strip().lower()


def similar(a: str, b: str, threshold: float = SIMILARITY_THRESHOLD) -> bool:
    if a == b:
        return True
    matcher = SequenceMatcher(None, a, b, autojunk=False)
    return (
        matcher.real_quick_ratio() >= threshold and matcher.quick_ratio() >= threshold and matcher.ratio() >= threshold
    )


def _final_path(url: str) -> str:
    parts = urlsplit(url)
    return f"{parts.hostname}:{parts.port}{parts.path}"


@dataclass(frozen=True)
class Probe:
    final_url: str
    redirected: bool
    text: str


@dataclass(frozen=True)
class Soft404Profile:
    """What a missing page looks like on this site; empty when missing pages are real 404s."""

    probes: tuple[Probe, ...] = ()

    def looks_missing(self, resp, body: bytes, requested_path: str) -> bool:
        if resp is None or resp.status_code != 200:
            return False
        text = normalize(body, requested_path)
        for probe in self.probes:
            # Every unknown path was sent to the same page (e.g. /login): so was this one.
            if probe.redirected and resp.history and _final_path(resp.url) == _final_path(probe.final_url):
                return True
            if similar(text, probe.text):
                return True
        return False


def build_profile(session, base_url: str) -> Soft404Profile:
    """Probe one random file-like and one random directory-like path (random per scan)."""
    probes = []
    for path in (f"owasp-scanner-probe-{secrets.token_hex(6)}.txt", f"owasp-scanner-probe-{secrets.token_hex(6)}/"):
        resp, body, err = get_limited(session, urljoin(base_url, path))
        if err or resp is None or resp.status_code != 200:
            continue
        probes.append(Probe(resp.url, bool(resp.history), normalize(body, path)))
    return Soft404Profile(tuple(probes))
