from owasp_tool.checks.security_headers import SecurityHeadersCheck


def _titles(findings):
    return {f.title for f in findings}


def test_reports_missing_headers_on_https(mock_client):
    findings = SecurityHeadersCheck().run(mock_client(), "https://example.test")
    assert _titles(findings) == {
        "Missing header: Content-Security-Policy",
        "Missing header: X-Content-Type-Options",
        "Missing header: X-Frame-Options",
        "Missing header: Strict-Transport-Security",
    }


def test_hsts_not_required_on_http(mock_client):
    findings = SecurityHeadersCheck().run(mock_client(), "http://example.test")
    assert "Missing header: Strict-Transport-Security" not in _titles(findings)


def test_no_findings_when_headers_present(mock_client):
    client = mock_client(
        headers={
            "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
            "X-Content-Type-Options": "nosniff",
            "Strict-Transport-Security": "max-age=31536000",
        }
    )
    assert SecurityHeadersCheck().run(client, "https://example.test") == []
