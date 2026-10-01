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
from dataclasses import replace

from cryptography import x509

from ..catalog import CVSS_TLS_CIPHER_BROKEN_BUT_ENCRYPTING
from ..http_utils import url_host
from ..models import Finding, Severity
from ..rule_loader import is_interceptor_issuer

_WEAK_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}
_CERT_EXPIRY_WARN_DAYS = 30

# FR-DET-17. Markers as they appear in OpenSSL suite names (what ssl.cipher() returns),
# most serious reason first: a suite is reported under the first reason that matches, so
# EXP-RC2-CBC-MD5 is reported as export grade rather than as RC2.
# "no-encryption" and "unauthenticated" leave an on-path attacker a free hand, so they keep
# the catalog's worst case; "broken" suites still encrypt, so they score lower (FR-MODEL-03).
_WEAK_CIPHER_MARKERS: tuple[tuple[str, str, str], ...] = (
    ("NULL", "no-encryption", "does not encrypt the traffic at all"),
    # OpenSSL spells export suites EXP-RC4-MD5 / EXP1024-DES-CBC-SHA; IANA names carry EXPORT.
    ("EXP-", "no-encryption", "is export grade, so its key is 40-56 bits by design"),
    ("EXP1024", "no-encryption", "is export grade, so its key is 40-56 bits by design"),
    ("EXPORT", "no-encryption", "is export grade, so its key is 40-56 bits by design"),
    ("ADH-", "unauthenticated", "authenticates neither side, so an on-path attacker can take over the session"),
    ("AECDH-", "unauthenticated", "authenticates neither side, so an on-path attacker can take over the session"),
    ("RC4", "broken", "uses RC4, a stream cipher with practical plaintext-recovery attacks (RFC 7465)"),
    ("RC2", "broken", "uses RC2, a 64-bit block cipher no longer considered safe"),
    # Matches single DES (DES-CBC-SHA, 56-bit) and 3DES (DES-CBC3-SHA, 64-bit block, SWEET32).
    ("DES", "broken", "uses DES/3DES: a 56-bit key or a 64-bit block (SWEET32)"),
    ("IDEA", "broken", "uses IDEA, a 64-bit block cipher dropped from TLS 1.2 onwards"),
    ("MD5", "broken", "authenticates records with MD5, which is no longer collision resistant"),
)
_WORST_CASE_REASONS = ("no-encryption", "unauthenticated")


def weak_cipher_reason(cipher_name: str) -> str | None:
    """``"no-encryption"``, ``"unauthenticated"``, ``"broken"``, or None if the suite is fine."""
    return next((reason for marker, reason, _ in _WEAK_CIPHER_MARKERS if marker in cipher_name), None)


def _weak_cipher_explanation(cipher_name: str) -> str:
    return next(text for marker, _, text in _WEAK_CIPHER_MARKERS if marker in cipher_name)


def cipher_cvss_vector(cipher_name: str) -> str:
    """Per-instance CVSS vector for a weak cipher (FR-MODEL-03).

    Empty means "keep the catalog's worst case": nothing left to break (no encryption, or
    nobody authenticated). Suites that are broken but still encrypting score lower.
    """
    if weak_cipher_reason(cipher_name) in _WORST_CASE_REASONS:
        return ""
    return CVSS_TLS_CIPHER_BROKEN_BUT_ENCRYPTING


def _weak_cipher_findings(url: str, hostname: str, port: int, cipher) -> list[Finding]:
    """FR-TLS-04: one finding when the negotiated suite is weak, saying why it is weak."""
    name = cipher[0] if cipher else ""
    if not name or not weak_cipher_reason(name):
        return []
    return [
        Finding(
            id="TLS-WEAK-CIPHER",
            title=f"Weak cipher suite negotiated: {name}",
            severity=Severity.HIGH,
            owasp_category="A02:2021 - Cryptographic Failures",
            description=f"The negotiated cipher suite {_weak_cipher_explanation(name)}.",
            recommendation="Restrict the server's cipher list to modern AEAD suites (e.g. AES-GCM, ChaCha20).",
            evidence=f"Negotiated cipher suite: {name}",
            url=url,
            instance_key=f"{hostname}:{port}",
            cvss_vector=cipher_cvss_vector(name),
        )
    ]


def _fetch_raw_cert_and_connection_info(hostname: str, port: int, timeout: int):
    """Step 1: non-verifying connection. Returns (der_cert, protocol, cipher, error)."""
    insecure_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    insecure_ctx.check_hostname = False
    insecure_ctx.verify_mode = ssl.CERT_NONE
    # This connection measures what the server accepts, so it must also reach servers that
    # only speak TLS 1.0/1.1 or legacy ciphers: Python's defaults (TLS 1.2+, SECLEVEL 2)
    # would turn TLS-WEAK-PROTOCOL into TLS-CONN-FAILED. DEFAULT stays first, so a modern
    # server negotiates what it negotiates with any client. Step 2 keeps strict defaults.
    insecure_ctx.minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED
    insecure_ctx.set_ciphers("DEFAULT:ALL:@SECLEVEL=0")

    try:
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with insecure_ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                der_cert = ssock.getpeercert(binary_form=True)
                protocol = ssock.version()
                cipher = ssock.cipher()
        return der_cert, protocol, cipher, None
    except OSError as exc:  # timeouts, DNS, refused connections and ssl.SSLError are all OSError
        return None, None, None, exc


def _verify_trust(hostname: str, port: int, timeout: int, trust: ssl.SSLContext | None = None):
    """Step 2: verifying connection. Returns None if trusted, or the raised exception."""
    verify_ctx = trust if trust is not None else ssl.create_default_context()
    try:
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with verify_ctx.wrap_socket(sock, server_hostname=hostname):
                pass
        return None
    except ssl.SSLCertVerificationError as exc:
        return exc
    except OSError:  # includes ssl.SSLError; SSLCertVerificationError is handled above
        # Connection-level failure here is not a trust finding; step 1 already
        # reports connectivity problems.
        return None


def check_tls(
    hostname: str,
    port: int = 443,
    timeout: int = 10,
    warnings: list[str] | None = None,
    trust: ssl.SSLContext | None = None,
) -> list[Finding]:
    """TLS checks; ``warnings`` receives a note when the handshake looks intercepted (FR-DET-16)."""
    findings: list[Finding] = []
    url = f"https://{url_host(hostname)}:{port}"

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
                instance_key=f"{hostname}:{port}",
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
                instance_key=f"{hostname}:{port}",
            )
        )

    findings.extend(_weak_cipher_findings(url, hostname, port, cipher))

    issuer = ""
    cert_time_problem = False  # tracks whether an expiry/not-yet-valid finding already explains any trust failure

    if der_cert:
        try:
            cert_obj = x509.load_der_x509_certificate(der_cert)
            issuer = cert_obj.issuer.rfc4514_string()
            not_after = cert_obj.not_valid_after_utc
            not_before = cert_obj.not_valid_before_utc
            now = datetime.datetime.now(datetime.UTC)

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
                        instance_key=f"{hostname}:{port}",
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
                        instance_key=f"{hostname}:{port}",
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
                            recommendation=(
                                "Renew the certificate (or confirm auto-renewal, e.g. ACME/Let's Encrypt, is working)."
                            ),
                            url=url,
                            instance_key=f"{hostname}:{port}",
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
                    instance_key=f"{hostname}:{port}",
                )
            )

    # Only run the trust-chain check when the certificate's own validity
    # period is fine — otherwise a self-signed-style verification failure
    # would just re-state the expiry/not-yet-valid finding above.
    if not cert_time_problem:
        trust_err = _verify_trust(hostname, port, timeout, trust)
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
                    instance_key=f"{hostname}:{port}",
                )
            )

    if issuer and is_interceptor_issuer(issuer):
        # FR-DET-16: we measured the interceptor (antivirus web shield, TLS-inspection proxy),
        # not the server; its protocol, cipher and certificate say little about the target.
        if warnings is not None:
            warnings.append(
                f"TLS to {hostname}:{port} appears to be intercepted by local software or a proxy "
                f"(certificate issued by {issuer!r}); TLS results describe the interceptor, not the server, "
                "and are marked low confidence. Scan from a machine without TLS inspection."
            )
        findings = [replace(f, confidence="low") for f in findings]

    return findings
