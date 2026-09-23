import httpx

from owasp_tool.checks.base import Check
from owasp_tool.models import Finding, Severity

# header -> (severity, recommendation)
_EXPECTED_HEADERS = {
    "Content-Security-Policy": (
        Severity.MEDIUM,
        "Define a Content-Security-Policy that restricts script and resource sources.",
    ),
    "X-Content-Type-Options": (
        Severity.LOW,
        "Set 'X-Content-Type-Options: nosniff'.",
    ),
    "X-Frame-Options": (
        Severity.LOW,
        "Set 'X-Frame-Options: DENY' or use the CSP 'frame-ancestors' directive.",
    ),
}


class SecurityHeadersCheck(Check):
    id = "security-headers"
    name = "Missing HTTP security headers"
    owasp = "A05:2021 Security Misconfiguration"
    description = "Passive check: one GET request, inspects response headers."

    def run(self, client: httpx.Client, target: str) -> list[Finding]:
        response = client.get(target)
        headers = response.headers
        expected = dict(_EXPECTED_HEADERS)

        if response.url.scheme == "https":
            expected["Strict-Transport-Security"] = (
                Severity.MEDIUM,
                "Set 'Strict-Transport-Security: max-age=31536000; includeSubDomains'.",
            )
        if "frame-ancestors" in headers.get("Content-Security-Policy", ""):
            expected.pop("X-Frame-Options")

        return [
            Finding(
                check_id=self.id,
                title=f"Missing header: {header}",
                severity=severity,
                description=f"The response from {response.url} does not include {header}.",
                evidence=f"HTTP {response.status_code} {response.url}",
                recommendation=recommendation,
                owasp=self.owasp,
            )
            for header, (severity, recommendation) in expected.items()
            if header not in headers
        ]
