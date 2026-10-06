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

A third group of connections, the probes of ``tls_probe`` (FR-DET-04), asks which protocol
versions and weak cipher groups the server accepts beyond the one that step 1 negotiated.

Maps to OWASP Top 10 A02:2021 (Cryptographic Failures) and ASVS V9
(Communications).
"""

from __future__ import annotations

import base64
import datetime
import socket
import ssl
from dataclasses import replace
from urllib.parse import urlsplit

from cryptography import x509

from .. import rule_loader
from ..catalog import CVSS_TLS_CIPHER_BROKEN_BUT_ENCRYPTING
from ..http_utils import USER_AGENT, check_peer, url_host
from ..models import Finding, Severity
from ..request_options import proxy_credentials
from ..rule_loader import CipherGroup, TlsProbeRules, is_interceptor_issuer
from . import tls_probe

_WEAK_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}
_CERT_EXPIRY_WARN_DAYS = 30

# FR-DET-17. What makes a suite weak, and why, is declared in rules/tls_probe.json: each group lists the
# markers that recognise it in an OpenSSL suite name (what ssl.cipher() returns), most serious first, so a
# suite is reported under the first group that matches (EXP-RC2-CBC-MD5 is export grade, not RC2).
# "no-encryption" and "unauthenticated" leave an on-path attacker a free hand, so they keep the catalog's
# worst case; "broken" suites still encrypt, so they score lower (FR-MODEL-03).
_WORST_CASE_REASONS = ("no-encryption", "unauthenticated")


def weak_cipher_reason(cipher_name: str) -> str | None:
    """``"no-encryption"``, ``"unauthenticated"``, ``"broken"``, or None if the suite is fine."""
    group = rule_loader.cipher_group_of(cipher_name)
    return group.reason if group else None


def _group_cvss_vector(group: CipherGroup) -> str:
    """Per-instance CVSS vector for a weak cipher group (FR-MODEL-03).

    Empty means "keep the catalog's worst case": nothing left to break (no encryption, or
    nobody authenticated). Suites that are broken but still encrypting score lower.
    """
    return "" if group.reason in _WORST_CASE_REASONS else CVSS_TLS_CIPHER_BROKEN_BUT_ENCRYPTING


def cipher_cvss_vector(cipher_name: str) -> str:
    group = rule_loader.cipher_group_of(cipher_name)
    return _group_cvss_vector(group) if group else ""


def _suite_label(group: CipherGroup, code: int) -> str:
    name = next((s.name for s in group.suites if s.code == code), None)
    return f"{name} (0x{code:04X})" if name else f"0x{code:04X}"


def _weak_cipher_findings(
    url: str,
    hostname: str,
    port: int,
    cipher,
    report: tls_probe.ProbeReport | None = None,
    rules: TlsProbeRules | None = None,
) -> list[Finding]:
    """FR-TLS-04, FR-TLS-13: one finding per weak cipher group the server accepts.

    A group is accepted when the connection that read the certificate negotiated one of its suites,
    or when a probe offered only that group and the server chose a suite from it. Either way the
    group is one finding, keyed ``host:port:<GROUP>``, and the evidence says how it was seen.
    """
    rules = rules or rule_loader.load_tls_probe()
    name = cipher[0] if cipher else ""
    negotiated = rule_loader.cipher_group_of(name) if name else None
    findings = []
    for group in rules.groups:
        seen = []
        if negotiated is not None and negotiated.id == group.id:
            seen.append(f"Negotiated cipher suite: {name}")
        result = report.groups.get(group.id) if report else None
        if result is not None and result.outcome is tls_probe.Outcome.ACCEPTED:
            seen.append(
                "Accepted in a probe handshake: the server selected "
                f"{_suite_label(group, result.suite or 0)} when offered only {group.title} suites"
            )
        if not seen:
            continue
        findings.append(
            Finding(
                id="TLS-WEAK-CIPHER",
                title=f"Weak cipher suites enabled: {group.title}",
                severity=Severity.HIGH,
                owasp_category="A02:2021 - Cryptographic Failures",
                description=f"A cipher suite the server accepts {group.description}.",
                recommendation="Restrict the server's cipher list to modern AEAD suites (e.g. AES-GCM, ChaCha20).",
                evidence="; ".join(seen),
                url=url,
                instance_key=f"{hostname}:{port}:{group.id}",
                cvss_vector=_group_cvss_vector(group),
            )
        )
    return findings


_PROTOCOL_NOTES = {
    "SSLv3": "SSLv3 is broken (POODLE) and was retired by RFC 7568",
    "TLSv1": "TLS 1.0 was deprecated by RFC 8996",
    "TLSv1.1": "TLS 1.1 was deprecated by RFC 8996",
}


def _weak_protocol_findings(
    url: str,
    hostname: str,
    port: int,
    negotiated: str | None,
    report: tls_probe.ProbeReport | None = None,
    rules: TlsProbeRules | None = None,
) -> list[Finding]:
    """FR-TLS-03, FR-TLS-12: one finding per weak protocol version the server accepts."""
    rules = rules or rule_loader.load_tls_probe()
    names = [p.name for p in rules.protocols if p.weak]
    if negotiated in _WEAK_PROTOCOLS and negotiated not in names:
        names.append(negotiated)  # e.g. SSLv2: negotiated by a legacy server, never probed
    findings = []
    for name in names:
        seen = []
        if negotiated == name:
            seen.append(f"Negotiated by the connection that read the certificate: {name}")
        result = report.protocols.get(name) if report else None
        if result is not None and result.outcome is tls_probe.Outcome.ACCEPTED:
            seen.append(f"Accepted in a probe handshake: the server replied with a ServerHello for {name}")
        if not seen:
            continue
        note = _PROTOCOL_NOTES.get(name, f"{name} is deprecated")
        findings.append(
            Finding(
                id="TLS-WEAK-PROTOCOL",
                title=f"Weak TLS protocol enabled: {name}",
                severity=Severity.HIGH,
                owasp_category="A02:2021 - Cryptographic Failures",
                description=f"The server accepts {name}, which is insecure: {note}.",
                recommendation="Disable protocols below TLS 1.2 (prefer TLS 1.3) in the server/load balancer config.",
                evidence="; ".join(seen),
                url=url,
                instance_key=f"{hostname}:{port}:{name}",
            )
        )
    return findings


def _untested_notes(report: tls_probe.ProbeReport, hostname: str, port: int, rules: TlsProbeRules) -> list[str]:
    """FR-TLS-14: what the probes could not test, once per reason, so a gap is never a silent pass."""
    by_reason: dict[str, list[str]] = {}
    for name, result in report.protocols.items():
        if result.outcome is tls_probe.Outcome.ERROR:
            by_reason.setdefault(result.detail, []).append(name)
    titles = {g.id: g.title for g in rules.groups}
    for group_id, result in report.groups.items():
        if result.outcome is tls_probe.Outcome.ERROR:
            by_reason.setdefault(result.detail, []).append(f"{titles[group_id]} cipher suites")
    return [
        f"Could not test whether {hostname}:{port} accepts {', '.join(what)} ({reason})"
        for reason, what in by_reason.items()
    ]


_MAX_PROXY_RESPONSE = 16 * 1024
_CRLF = "\r\n"
_END_OF_HEADERS = b"\r\n\r\n"


def _open_connection(
    hostname: str, port: int, timeout: int, proxy: str | None = None, connect_guard=None
) -> socket.socket:
    """A TCP connection to ``hostname:port``, through an http:// proxy's CONNECT tunnel if one is set.

    The TLS check opens its own sockets rather than going through the HTTP session, so without
    this it would connect directly even when the operator asked for a proxy (FR-CI-07): on a
    network that blocks direct connections that is a false TLS-CONN-FAILED, and elsewhere it
    exposes the scanner's address that the proxy was meant to hide.
    """
    if not proxy:
        return check_peer(socket.create_connection((hostname, port), timeout=timeout), connect_guard)
    parts = urlsplit(proxy)
    sock = socket.create_connection((parts.hostname, parts.port or 80), timeout=timeout)
    try:
        authority = f"{url_host(hostname)}:{port}"
        lines = [f"CONNECT {authority} HTTP/1.1", f"Host: {authority}", f"User-Agent: {USER_AGENT}"]
        creds = proxy_credentials(proxy)
        if creds is not None:
            token = base64.b64encode(f"{creds[0]}:{creds[1]}".encode()).decode("ascii")
            lines.append(f"Proxy-Authorization: Basic {token}")
        sock.sendall((_CRLF.join(lines) + _CRLF + _CRLF).encode("latin-1"))
        response = b""
        while _END_OF_HEADERS not in response:
            chunk = sock.recv(4096)
            if not chunk:
                raise OSError("the proxy closed the connection during CONNECT")
            response += chunk
            if len(response) > _MAX_PROXY_RESPONSE:
                raise OSError("the proxy's CONNECT response is too long")
        status_line = response.split(_CRLF.encode("ascii"), 1)[0].decode("latin-1", "replace")
        fields = status_line.split()
        if len(fields) < 2 or fields[1] != "200":
            raise OSError(f"the proxy refused CONNECT {authority}: {status_line}")
        return sock
    except BaseException:
        sock.close()
        raise


def _fetch_raw_cert_and_connection_info(
    hostname: str, port: int, timeout: int, limiter=None, proxy=None, connect_guard=None
):
    """Step 1: non-verifying connection. Returns (der_cert, protocol, cipher, error)."""
    if limiter is not None:
        limiter.acquire(f"https://{hostname}:{port}/")  # a handshake is traffic too (FR-AUTHZ-05)
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
        with _open_connection(hostname, port, timeout, proxy, connect_guard) as sock:
            with insecure_ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                der_cert = ssock.getpeercert(binary_form=True)
                protocol = ssock.version()
                cipher = ssock.cipher()
        return der_cert, protocol, cipher, None
    except OSError as exc:  # timeouts, DNS, refused connections and ssl.SSLError are all OSError
        return None, None, None, exc


def _verify_trust(
    hostname: str,
    port: int,
    timeout: int,
    trust: ssl.SSLContext | None = None,
    limiter=None,
    proxy=None,
    connect_guard=None,
):
    """Step 2: verifying connection. Returns None if trusted, or the raised exception."""
    verify_ctx = trust if trust is not None else ssl.create_default_context()
    if limiter is not None:
        limiter.acquire(f"https://{hostname}:{port}/")
    try:
        with _open_connection(hostname, port, timeout, proxy, connect_guard) as sock:
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
    limiter=None,
    proxy: str | None = None,
    probe: bool = True,
    connect_guard=None,
) -> list[Finding]:
    """TLS checks; ``warnings`` receives a note when the handshake looks intercepted (FR-DET-16)
    and one for every probe that could not run (FR-TLS-14). ``probe=False`` skips the probes.

    ``connect_guard(ip) -> bool`` is asked about the address of every connection this check opens (the two
    certificate connections and the probes) before anything is sent; see ``http_utils.check_peer``."""
    # Passed on only when set, so a helper that is replaced in a test keeps its old signature.
    guard = {"connect_guard": connect_guard} if connect_guard is not None else {}
    findings: list[Finding] = []
    url = f"https://{url_host(hostname)}:{port}"

    der_cert, protocol, cipher, conn_err = _fetch_raw_cert_and_connection_info(
        hostname, port, timeout, limiter, proxy, **guard
    )
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

    report = rules = None
    if probe:
        rules = rule_loader.load_tls_probe()  # looked up at call time so a test can substitute the rules
        report = tls_probe.run_probes(
            hostname,
            port,
            timeout,
            rules,
            connect=lambda host, tcp_port, seconds: _open_connection(host, tcp_port, seconds, proxy, connect_guard),
            limiter=limiter,  # every probe is a connection: --rate-limit and --max-requests apply (FR-AUTHZ-05)
        )
        if warnings is not None:
            warnings.extend(_untested_notes(report, hostname, port, rules))

    findings.extend(_weak_protocol_findings(url, hostname, port, protocol, report, rules))
    findings.extend(_weak_cipher_findings(url, hostname, port, cipher, report, rules))

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
        trust_err = _verify_trust(hostname, port, timeout, trust, limiter, proxy, **guard)
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
