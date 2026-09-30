"""FR-MODEL-01: cwe, confidence, references, instance_key and fingerprint on every finding."""

from __future__ import annotations

import re

import pytest
from conftest import QuietHandler
from mock_server import Handler as MockHandler

from owasp_scanner import catalog, cli
from owasp_scanner.checks import cookies, exposure, headers
from owasp_scanner.models import Finding, Severity

FINGERPRINT = re.compile(r"^[0-9a-f]{32}$")


class EverythingHandler(QuietHandler):
    """A target that triggers as many different finding types as possible over HTTP."""

    def do_GET(self):
        path = self.path.split("?")[0]
        if path == "/":
            self.send(
                200,
                b"home",
                [
                    ("Content-Security-Policy", "script-src 'unsafe-inline'"),
                    ("X-Frame-Options", "ALLOWALL"),
                    ("X-XSS-Protection", "1; mode=block"),
                    ("Server", "nginx/1.0"),
                    ("X-Powered-By", "PHP/5"),
                    ("Set-Cookie", "a=1; Path=/"),
                    ("Set-Cookie", "b=2; Secure; HttpOnly"),
                    ("Access-Control-Allow-Origin", self.headers.get("Origin") or "*"),
                ],
            )
        elif path == "/robots.txt":
            self.send(200, b"Disallow: /admin/\n")
        elif path == "/sitemap.xml":
            self.send(200, b"<urlset><url><loc>http://x/staging/</loc></url></urlset>")
        elif path == "/images/":
            self.send(200, b"<title>Index of /images</title>")
        elif path in ("/.env", "/.git/HEAD", "/.well-known/security.txt"):
            self.send(200, b"x")
        else:
            self.send(404)


def all_known_ids() -> set[str]:
    ids = {f"HDR-{h.upper()}-MISSING" for h in headers._REQUIRED_HEADERS}
    ids |= {f"HDR-INFO-{h.upper()}" for h in headers._INFO_LEAK_HEADERS}
    ids |= {"HDR-XFO-WEAK", "HDR-CSP-UNSAFE", "HDR-XXP-LEGACY", "COOKIE-FLAGS-MISSING"}
    ids |= {fid for fid, _, _ in exposure._SENSITIVE_PATHS.values()}
    ids |= {"EXPOSURE-DIR-LISTING", "EXPOSURE-ROBOTS-HINTS", "EXPOSURE-SITEMAP-HINTS"}
    ids |= {"CORS-WILDCARD-WITH-CREDENTIALS", "CORS-REFLECTS-ARBITRARY-ORIGIN", "CORS-WILDCARD"}
    ids |= {
        "TLS-CONN-FAILED",
        "TLS-WEAK-PROTOCOL",
        "TLS-WEAK-CIPHER",
        "TLS-CERT-NOT-YET-VALID",
        "TLS-CERT-EXPIRED",
        "TLS-CERT-EXPIRING-SOON",
        "TLS-CERT-NOT-TRUSTED",
        "TLS-CERT-PARSE-FAILED",
        "TLS-NO-HTTPS-REDIRECT",
    }
    return ids


def test_catalog_covers_every_finding_id():
    assert all_known_ids() == set(catalog.FINDING_CATALOG)


@pytest.mark.parametrize("finding_id", sorted(all_known_ids()))
def test_catalog_entries_are_complete(finding_id):
    meta = catalog.FINDING_CATALOG[finding_id]
    assert meta.confidence in ("high", "medium", "low")
    assert meta.references and all(ref.startswith("https://") for ref in meta.references)
    if finding_id in catalog.NOT_A_WEAKNESS:
        assert meta.cwe == ""
    else:
        assert re.fullmatch(r"CWE-\d+", meta.cwe)


def test_every_finding_of_a_real_scan_is_enriched(http_server):
    result = cli.run_scan(http_server(EverythingHandler))
    assert len({f.id for f in result.findings}) >= 15
    for f in result.findings:
        assert f.instance_key, f.id
        assert FINGERPRINT.match(f.fingerprint), f.id
        assert f.confidence in ("high", "medium", "low"), f.id
        assert f.references, f.id
        assert f.cwe or f.id in catalog.NOT_A_WEAKNESS, f.id


def test_same_type_in_two_places_gets_two_fingerprints(http_server):
    result = cli.run_scan(http_server(EverythingHandler))
    cookie_findings = [f for f in result.findings if f.id == "COOKIE-FLAGS-MISSING"]
    assert sorted(f.instance_key for f in cookie_findings) == ["a", "b"]
    assert len({f.fingerprint for f in cookie_findings}) == 2


def test_fingerprints_are_stable_across_scans(http_server):
    base = http_server(MockHandler)
    first = {f.fingerprint for f in cli.run_scan(base).findings}
    second = {f.fingerprint for f in cli.run_scan(base).findings}
    assert first == second and len(first) == len(cli.run_scan(base).findings)


def _finding(finding_id="HDR-CSP-UNSAFE", instance_key="content-security-policy"):
    return Finding(
        id=finding_id,
        title="t",
        severity=Severity.MEDIUM,
        owasp_category="c",
        description="d",
        instance_key=instance_key,
    )


def test_fingerprint_uses_origin_not_path_or_time():
    a = catalog.enrich(_finding(), "https://Example.com/")
    b = catalog.enrich(_finding(), "https://example.com:443/app/?q=1")
    c = catalog.enrich(_finding(), "http://example.com/")
    d = catalog.enrich(_finding(), "https://other.example/")
    assert a.fingerprint == b.fingerprint
    assert len({a.fingerprint, c.fingerprint, d.fingerprint}) == 3


def test_fingerprint_depends_on_id_and_instance():
    target = "https://example.com/"
    base = catalog.enrich(_finding(), target).fingerprint
    assert catalog.enrich(_finding(finding_id="HDR-XXP-LEGACY"), target).fingerprint != base
    assert catalog.enrich(_finding(instance_key="other"), target).fingerprint != base


@pytest.mark.parametrize(
    "raw, cwe",
    [
        ("s=1; HttpOnly; SameSite=Lax", "CWE-614"),  # Secure missing
        ("s=1; Secure; SameSite=Lax", "CWE-1004"),  # only HttpOnly missing
        ("s=1; Secure; HttpOnly", "CWE-1275"),  # only SameSite missing
    ],
)
def test_cookie_cwe_follows_the_most_important_missing_attribute(raw, cwe):
    (finding,) = cookies.check_cookies("https://t/", [raw])
    assert catalog.enrich(finding, "https://t/").cwe == cwe


def test_new_fields_are_serialized():
    data = catalog.enrich(_finding(), "https://example.com/").to_dict()
    assert {"cwe", "confidence", "references", "instance_key", "fingerprint"} <= set(data)
