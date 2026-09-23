"""Passive checks for accidentally exposed sensitive files/paths and
directory listings.

Only ordinary GET requests to well-known, publicly-documented paths
are sent — nothing that probes for or exploits a vulnerability.
Maps to OWASP Top 10 A01:2021 (Broken Access Control) and
A05:2021 (Security Misconfiguration).
"""
from __future__ import annotations

import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin, urlparse

from ..http_utils import safe_get
from ..models import Finding, Severity

# path -> (stable finding id, severity, short label)
# The id is declared explicitly (not derived from the path string) so it
# stays stable and collision-free regardless of how a path is spelled.
_SENSITIVE_PATHS = {
    ".git/HEAD": ("EXPOSURE-GIT-HEAD", Severity.CRITICAL, "Exposed .git repository metadata"),
    ".git/config": ("EXPOSURE-GIT-CONFIG", Severity.CRITICAL, "Exposed .git repository config"),
    ".env": ("EXPOSURE-ENV", Severity.CRITICAL, "Exposed .env file (often contains secrets)"),
    ".env.local": ("EXPOSURE-ENV-LOCAL", Severity.CRITICAL, "Exposed .env.local file"),
    ".env.production": ("EXPOSURE-ENV-PRODUCTION", Severity.CRITICAL, "Exposed .env.production file"),
    "wp-config.php.bak": ("EXPOSURE-WP-CONFIG-BAK", Severity.CRITICAL, "Exposed WordPress config backup"),
    "config.php.bak": ("EXPOSURE-CONFIG-PHP-BAK", Severity.CRITICAL, "Exposed config backup file"),
    "web.config": ("EXPOSURE-WEB-CONFIG", Severity.MEDIUM, "Exposed IIS web.config"),
    ".svn/entries": ("EXPOSURE-SVN-ENTRIES", Severity.HIGH, "Exposed Subversion metadata"),
    ".DS_Store": ("EXPOSURE-DS-STORE", Severity.LOW, "Exposed macOS .DS_Store (can leak file listing)"),
    "docker-compose.yml": ("EXPOSURE-DOCKER-COMPOSE", Severity.HIGH, "Exposed docker-compose.yml"),
    "backup.zip": ("EXPOSURE-BACKUP-ZIP", Severity.HIGH, "Exposed backup archive"),
    "backup.sql": ("EXPOSURE-BACKUP-SQL", Severity.CRITICAL, "Exposed SQL database dump"),
    "phpinfo.php": ("EXPOSURE-PHPINFO", Severity.MEDIUM, "Exposed phpinfo() output"),
    "server-status": ("EXPOSURE-SERVER-STATUS", Severity.MEDIUM, "Exposed Apache mod_status page"),
    "id_rsa": ("EXPOSURE-ID-RSA", Severity.CRITICAL, "Exposed private SSH key"),
    ".well-known/security.txt": ("EXPOSURE-SECURITY-TXT", Severity.INFO, "security.txt present (informational, not a finding)"),
}

_SENSITIVE_KEYWORDS = ("admin", "backup", "config", "internal", "private", "secret", "staging", "test")

_LISTING_MARKERS = ("Index of /", "<title>Index of", "Directory Listing For")


def check_sensitive_paths(session, base_url: str, max_workers: int = 5) -> list[Finding]:
    findings: list[Finding] = []

    # Baseline: request a clearly-nonexistent path to detect "soft 404" behavior
    # (custom error pages that return HTTP 200), so we don't report false positives.
    probe_url = urljoin(base_url, "owasp-scanner-nonexistent-probe-4f8c2b/")
    probe_resp, _ = safe_get(session, probe_url)
    soft_404 = probe_resp is not None and probe_resp.status_code == 200

    def fetch(path):
        url = urljoin(base_url, path)
        resp, err = safe_get(session, url)
        return path, url, resp, err

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = [pool.submit(fetch, p) for p in _SENSITIVE_PATHS]
        for fut in as_completed(futures):
            path, url, resp, err = fut.result()
            if err or resp is None:
                continue
            finding_id, severity, label = _SENSITIVE_PATHS[path]
            if path == ".well-known/security.txt":
                if resp.status_code == 200 and not soft_404:
                    findings.append(
                        Finding(
                            id=finding_id,
                            title=label,
                            severity=Severity.INFO,
                            owasp_category="A05:2021 - Security Misconfiguration",
                            description="A security.txt disclosure policy was found (good practice).",
                            url=url,
                        )
                    )
                continue

            if resp.status_code == 200 and not soft_404:
                findings.append(
                    Finding(
                        id=finding_id,
                        title=label,
                        severity=severity,
                        owasp_category="A01:2021 - Broken Access Control",
                        description=f"GET {path} returned HTTP 200, suggesting the file/path is publicly accessible.",
                        evidence=f"HTTP {resp.status_code} for {url}",
                        recommendation="Remove the file from the web root or block access at the web server/proxy layer.",
                        url=url,
                    )
                )

    return findings


def check_directory_listing(session, base_url: str, paths: list[str] | None = None) -> list[Finding]:
    findings: list[Finding] = []
    paths = paths or ["images/", "uploads/", "backup/", "files/", "assets/", "static/"]

    for path in paths:
        url = urljoin(base_url, path)
        resp, err = safe_get(session, url)
        if err or resp is None or resp.status_code != 200:
            continue
        body = resp.text[:2000] if resp.text else ""
        if any(marker in body for marker in _LISTING_MARKERS):
            findings.append(
                Finding(
                    id="EXPOSURE-DIR-LISTING",
                    title=f"Directory listing enabled at /{path}",
                    severity=Severity.MEDIUM,
                    owasp_category="A05:2021 - Security Misconfiguration",
                    description="The web server returns a browsable file index instead of a 403/404.",
                    evidence=url,
                    recommendation="Disable autoindex/directory listing in the web server configuration.",
                    url=url,
                )
            )

    return findings


def _check_robots_txt(session, base_url: str) -> list[Finding]:
    """robots.txt uses 'Disallow: <path>' directives."""
    findings: list[Finding] = []
    url = urljoin(base_url, "robots.txt")
    resp, err = safe_get(session, url)
    if err or resp is None or resp.status_code != 200:
        return findings

    body = resp.text or ""
    disallowed = [
        line.split(":", 1)[1].strip()
        for line in body.splitlines()
        if line.lower().startswith("disallow:") and line.split(":", 1)[1].strip()
    ]
    interesting = [p for p in disallowed if any(k in p.lower() for k in _SENSITIVE_KEYWORDS)]
    if interesting:
        findings.append(
            Finding(
                id="EXPOSURE-ROBOTS-HINTS",
                title="robots.txt lists sensitive-sounding paths",
                severity=Severity.LOW,
                owasp_category="A01:2021 - Broken Access Control",
                description=(
                    "robots.txt disallows crawling of paths that also sound sensitive; this doesn't "
                    "block direct access and can act as a roadmap for attackers."
                ),
                evidence=", ".join(interesting[:10]),
                recommendation="Enforce access control on these paths server-side; don't rely on robots.txt to hide them.",
                url=url,
            )
        )
    return findings


def _check_sitemap_xml(session, base_url: str) -> list[Finding]:
    """sitemap.xml lists URLs inside <loc>...</loc> tags (not Disallow: lines)."""
    findings: list[Finding] = []
    url = urljoin(base_url, "sitemap.xml")
    resp, err = safe_get(session, url)
    if err or resp is None or resp.status_code != 200:
        return findings

    body = resp.text or ""
    locations = re.findall(r"<loc>\s*(.*?)\s*</loc>", body, re.IGNORECASE | re.DOTALL)
    interesting = []
    for loc in locations:
        path = urlparse(loc).path or loc
        if any(k in path.lower() for k in _SENSITIVE_KEYWORDS):
            interesting.append(loc)

    if interesting:
        findings.append(
            Finding(
                id="EXPOSURE-SITEMAP-HINTS",
                title="sitemap.xml publicly lists sensitive-sounding URLs",
                severity=Severity.LOW,
                owasp_category="A01:2021 - Broken Access Control",
                description=(
                    "sitemap.xml advertises URLs whose path looks sensitive (admin/staging/internal/...); "
                    "unlike robots.txt this is actively published for crawlers to visit, so it is a "
                    "stronger disclosure signal."
                ),
                evidence=", ".join(interesting[:10]),
                recommendation="Remove sensitive/internal URLs from the public sitemap; enforce access control server-side.",
                url=url,
            )
        )
    return findings


def check_robots_and_sitemap(session, base_url: str) -> list[Finding]:
    return _check_robots_txt(session, base_url) + _check_sitemap_xml(session, base_url)
