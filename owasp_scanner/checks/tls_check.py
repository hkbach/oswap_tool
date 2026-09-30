"""TLS/certificate checks — connection only, no payloads.

Design note (fixed after review): certificate *trust* validation and
certificate *validity-period* validation are independent facts, but
Python's default SSLContext conflates them — an expired certificate
raises ``SSLCertVerificationError`` during the handshake itself, so a
single verifying connection can never reach the code that would read
``notAfter``. To report expiry (and protocol/cipher) even when the
chain is untrusted or expired, this module opens the connection twice:

1. A non-verifying connection, solely to read the raw certificate
   bytes and the negotiated protocol/cipher, regardless of trust.
2. A verifying connection (default trust store), run ONLY when step 1
   shows the certificate is within its validity window — used purely
   to detect trust-chain/hostname problems (self-signed, wrong CA,
   hostname mismatch) without duplicating an expiry finding.

Maps to OWASP Top 10 A02:2021 (Cryptographic Failures) and ASVS V9
(Communications).
"""
from __future__ import annotations

import datetime
import socket
import ssl

from cryptography import x509

from ..models import Finding, Severity

_WEAK_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}
_CERT_EXPIRY_WARN_DAYS = 30


def _not_valid_after(cert_obj) -> datetime.datetime:
    # cryptography >= 42 exposes tz-aware `not_valid_after_utc`; older
    # versions only have the naive `not_valid_after`.
    if hasattr(cert_obj, "not_valid_after_utc"):
        return cert_obj.not_valid_after_utc
    return cert_obj.not_valid_after.replace(tzinfo=datetime.timezone.utc)


def _not_valid_before(cert_obj) -> datetime.datetime:
    if hasattr(cert_obj, "not_valid_before_utc"):
        return cert_obj.not_valid_before_utc
    return cert_obj.not_valid_before.replace(tzinfo=datetime.timezone.utc)


def _fetch_raw_cert_and_connection_info(hostname: str, port: int, timeout: int):
    """Step 1: non-verifying connection. Returns (der_cert, protocol, cipher, error)."""
    insecure_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    insecure_ctx.check_hostname = False
    insecure_ctx.verify_mode = ssl.CERT_NONE

    try:
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with insecure_ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                der_cert = ssock.getpeercert(binary_form=True)
                protocol = ssock.version()
                cipher = ssock.cipher()
        return der_cert, protocol, cipher, None
    except (socket.timeout, socket.gaierror, ConnectionRefusedError, OSError, ssl.SSLError) as exc:
        return None, None, None, exc


def _verify_trust(hostname: str, port: int, timeout: int):
    """Step 2: verifying connection. Returns None if trusted, or the raised exception."""
    verify_ctx = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with verify_ctx.wrap_socket(sock, server_hostname=hostname):
                pass
        return None
    except ssl.SSLCertVerificationError as exc:
        return exc
    except (socket.timeout, socket.gaierror, ConnectionRefusedError, OSError, ssl.SSLError):
        # Connection-level failure here is not a trust finding; step 1 already
        # reports connectivity problems.
        return None


def check_tls(hostname: str, port: int = 443, timeout: int = 10) -> list[Finding]:
    findings: list[Finding] = []
    url = f"https://{hostname}:{port}"

    der_cert, protocol, cipher, conn_err = _fetch_raw_cert_and_connection_info(hostname, port, timeout)
    if conn_err is not None:
        findings.append(
            Finding(
                id="TLS-CONN-FAILED",
                title="Could not establish a TLS connection",
                severity=Severity.INFO,
                owasp_category="A02:2021 - Cryptographic Failures",
                description=f"Connection to {hostname}:{port} failed: {conn_err}",
                url=url,
            )
        )
        return findings

    if protocol in _WEAK_PROTOCOLS:
        findings.append(
            Finding(
                id="TLS-WEAK-PROTOCOL",
                title=f"Weak TLS protocol negotiated: {protocol}",
                severity=Severity.HIGH,
                owasp_category="A02:2021 - Cryptographic Failures",
                description=f"The server negotiated {protocol}, which is deprecated/insecure.",
                recommendation="Disable protocols below TLS 1.2 (prefer TLS 1.3) in the server/load balancer config.",
                url=url,
            )
        )

    if cipher and cipher[0] and any(weak in cipher[0] for weak in ("RC4", "3DES", "MD5", "NULL", "EXPORT")):
        findings.append(
            Finding(
                id="TLS-WEAK-CIPHER",
                title=f"Weak cipher suite negotiated: {cipher[0]}",
                severity=Severity.HIGH,
                owasp_category="A02:2021 - Cryptographic Failures",
                description=f"Negotiated cipher suite '{cipher[0]}' is considered weak.",
                recommendation="Restrict the server's cipher list to modern AEAD suites (e.g. AES-GCM, ChaCha20).",
                url=url,
            )
        )

    cert_time_problem = False  # tracks whether an expiry/not-yet-valid finding already explains any trust failure

    if der_cert:
        try:
            cert_obj = x509.load_der_x509_certificate(der_cert)
            not_after = _not_valid_after(cert_obj)
            not_before = _not_valid_before(cert_obj)
            now = datetime.datetime.now(datetime.timezone.utc)

            if now < not_before:
                cert_time_problem = True
                findings.append(
                    Finding(
                        id="TLS-CERT-NOT-YET-VALID",
                        title="TLS certificate is not yet valid",
                        severity=Severity.CRITICAL,
                        owasp_category="A02:2021 - Cryptographic Failures",
                        description=f"Certificate's validity period starts on {not_before.isoformat()}.",
                        recommendation="Check the certificate issuance date and the server/client clock for skew.",
                        url=url,
                    )
                )
            elif now > not_after:
                cert_time_problem = True
                findings.append(
                    Finding(
                        id="TLS-CERT-EXPIRED",
                        title="TLS certificate has expired",
                        severity=Severity.CRITICAL,
                        owasp_category="A02:2021 - Cryptographic Failures",
                        description=f"Certificate expired on {not_after.isoformat()}.",
                        recommendation="Renew the certificate immediately.",
                        url=url,
                    )
                )
            else:
                days_left = (not_after - now).days
                if days_left < _CERT_EXPIRY_WARN_DAYS:
                    findings.append(
                        Finding(
                            id="TLS-CERT-EXPIRING-SOON",
                            title=f"TLS certificate expires in {days_left} day(s)",
                            severity=Severity.MEDIUM,
                            owasp_category="A02:2021 - Cryptographic Failures",
                            description=f"Certificate expires on {not_after.isoformat()}.",
                            recommendation="Renew the certificate (or confirm auto-renewal, e.g. ACME/Let's Encrypt, is working).",
                            url=url,
                        )
                    )
        except Exception as exc:  # malformed certificate bytes, unsupported encoding, etc.
            findings.append(
                Finding(
                    id="TLS-CERT-PARSE-FAILED",
                    title="Could not parse the server's certificate",
                    severity=Severity.INFO,
                    owasp_category="A02:2021 - Cryptographic Failures",
                    description=f"Failed to decode the certificate for validity-period checks: {exc}",
                    url=url,
                )
            )

    # Only run the trust-chain check when the certificate's own validity
    # period is fine — otherwise a self-signed-style verification failure
    # would just re-state the expiry/not-yet-valid finding above.
    if not cert_time_problem:
        trust_err = _verify_trust(hostname, port, timeout)
        if trust_err is not None:
            findings.append(
                Finding(
                    id="TLS-CERT-NOT-TRUSTED",
                    title="TLS certificate chain failed trust validation",
                    severity=Severity.CRITICAL,
                    owasp_category="A02:2021 - Cryptographic Failures",
                    description=f"Certificate verification failed: {trust_err}",
                    recommendation=(
                        "Install a certificate issued by a CA trusted by standard clients, covering the "
                        "exact hostname, with a complete chain (including intermediates)."
                    ),
                    url=url,
                )
            )

    return findings
