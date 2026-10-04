"""Shared fixtures: local HTTP/HTTPS servers and throwaway certificates.

Everything binds to 127.0.0.1 on an ephemeral port; no test touches the
internet.
"""

from __future__ import annotations

import datetime
import ipaddress
import ssl
import sys
import threading
import warnings
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


@pytest.fixture(autouse=True)
def _no_proxy_for_loopback(monkeypatch):
    # Corporate proxy settings must not capture requests to the local test servers.
    monkeypatch.setenv("NO_PROXY", "127.0.0.1,localhost")
    monkeypatch.setenv("no_proxy", "127.0.0.1,localhost")


class QuietHandler(BaseHTTPRequestHandler):
    """Base handler: silent, with a small helper for sending responses."""

    def log_message(self, format, *args):
        pass

    def send(self, status, body=b"", headers=None):
        self.send_response(status)
        items = headers.items() if isinstance(headers, dict) else (headers or [])
        for k, v in items:
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body:
            self.wfile.write(body)


class _QuietServer(ThreadingHTTPServer):
    """A test server that does not print a traceback when a client hangs up mid-handshake."""

    def handle_error(self, request, client_address):
        if issubclass(sys.exc_info()[0] or Exception, OSError):  # includes ssl.SSLError, ConnectionError
            return
        super().handle_error(request, client_address)


def _start(server):
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


@pytest.fixture
def http_server():
    """Factory: http_server(HandlerClass) -> base URL 'http://127.0.0.1:<port>/'."""
    servers = []

    def factory(handler_cls):
        server = _start(_QuietServer(("127.0.0.1", 0), handler_cls))
        servers.append(server)
        return f"http://127.0.0.1:{server.server_address[1]}/"

    yield factory
    for server in servers:
        server.shutdown()
        server.server_close()


def make_self_signed_cert(tmp_path, not_before, not_after, name="cert", common_name="websec-scanner-test"):
    """Write a self-signed cert/key pair for 127.0.0.1 and return (certfile, keyfile).

    The OS trust store never knows it. It is marked as its own CA so a test can make
    requests trust it (REQUESTS_CA_BUNDLE); OpenSSL refuses a leaf without CA:TRUE as
    a trust anchor.
    """
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(
            x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]),
            critical=False,
        )
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .sign(key, hashes.SHA256())
    )
    certfile = tmp_path / f"{name}.pem"
    keyfile = tmp_path / f"{name}.key"
    certfile.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    keyfile.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return certfile, keyfile


def _utcnow():
    return datetime.datetime.now(datetime.UTC)


CERT_WINDOWS = {
    # expired since 2020, as in the SRS AT-10 verification
    "expired": lambda: (
        datetime.datetime(2019, 1, 1, tzinfo=datetime.UTC),
        datetime.datetime(2020, 1, 1, tzinfo=datetime.UTC),
    ),
    "valid": lambda: (_utcnow() - datetime.timedelta(days=1), _utcnow() + datetime.timedelta(days=365)),
    "expiring": lambda: (_utcnow() - datetime.timedelta(days=1), _utcnow() + datetime.timedelta(days=10)),
    "not_yet_valid": lambda: (_utcnow() + datetime.timedelta(days=10), _utcnow() + datetime.timedelta(days=400)),
}


def _only_legacy_version(ctx: ssl.SSLContext, version: ssl.TLSVersion) -> None:
    """Make a server accept only ``version`` (e.g. TLS 1.0), or skip if this OpenSSL cannot."""
    try:
        with warnings.catch_warnings():  # TLSv1/TLSv1_1 are deprecated: exactly what the test needs
            warnings.simplefilter("ignore", DeprecationWarning)
            ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
            ctx.minimum_version = ctx.maximum_version = version
    except (ssl.SSLError, ValueError) as exc:
        pytest.skip(f"this OpenSSL ({ssl.OPENSSL_VERSION}) cannot serve {version.name}: {exc}")


@pytest.fixture
def https_server(tmp_path):
    """Factory: https_server(HandlerClass, cert="expired"|"valid"|...) -> (base URL, port).

    Serves HTTP over TLS with a self-signed certificate that the OS trust
    store does not know, so a verifying client always rejects it.
    """
    servers = []

    def factory(handler_cls, cert="valid", common_name="websec-scanner-test", only_version=None):
        not_before, not_after = CERT_WINDOWS[cert]()
        certfile, keyfile = make_self_signed_cert(tmp_path, not_before, not_after, name=cert, common_name=common_name)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile=str(certfile), keyfile=str(keyfile))
        if only_version is not None:
            _only_legacy_version(ctx, only_version)
        server = _QuietServer(("127.0.0.1", 0), handler_cls)
        server.socket = ctx.wrap_socket(server.socket, server_side=True)
        _start(server)
        servers.append(server)
        port = server.server_address[1]
        return f"https://127.0.0.1:{port}/", port

    yield factory
    for server in servers:
        server.shutdown()
        server.server_close()


def skip_if_tls_is_intercepted(port: int, certfile) -> None:
    """Skip when local software (e.g. an antivirus "web shield") re-signs loopback TLS.

    Such software replaces the server certificate, so no CA file can make the
    client trust it. Tests that need a trusted handshake cannot run there.
    """
    import socket

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
        with ctx.wrap_socket(sock, server_hostname="127.0.0.1") as tls:
            seen = x509.load_der_x509_certificate(tls.getpeercert(binary_form=True))
    served = x509.load_pem_x509_certificate(certfile.read_bytes())
    if seen != served:
        pytest.skip(
            "TLS to 127.0.0.1 is intercepted on this machine (certificate issued by "
            f"{seen.issuer.rfc4514_string()!r}); run in an environment without TLS inspection"
        )


@pytest.fixture
def closed_port():
    """A loopback port with nothing listening on it."""
    import socket

    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def fake_tls():
    """Factory: fake_tls(Policy(...)) -> a started FakeTlsServer (tests/tls_fake_server.py).

    Speaks TLS only as far as a ServerHello or an alert, so it can stand in for SSLv3, RC4 or
    EXPORT servers that no OpenSSL on a developer machine can reproduce.
    """
    from tls_fake_server import FakeTlsServer

    servers = []

    def factory(policy=None):
        server = FakeTlsServer(policy).__enter__()
        servers.append(server)
        return server

    yield factory
    for server in servers:
        server.close()


@pytest.fixture(autouse=True)
def _no_pause_between_tls_probes(monkeypatch):
    """The probes wait a fraction of a second between connections (rules/tls_probe.json).

    Real waiting would add seconds to every test that scans an HTTPS server; the tests of the
    pause itself pass their own ``sleep`` and are unaffected.
    """
    from websec_scanner.checks import tls_probe

    monkeypatch.setattr(tls_probe, "_sleep", lambda seconds: None)
