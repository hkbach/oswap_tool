"""Shared fixtures: local HTTP/HTTPS servers and throwaway certificates.

Everything binds to 127.0.0.1 on an ephemeral port; no test touches the
internet.
"""
from __future__ import annotations

import datetime
import ipaddress
import ssl
import threading
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


def _start(server):
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


@pytest.fixture
def http_server():
    """Factory: http_server(HandlerClass) -> base URL 'http://127.0.0.1:<port>/'."""
    servers = []

    def factory(handler_cls):
        server = _start(ThreadingHTTPServer(("127.0.0.1", 0), handler_cls))
        servers.append(server)
        return f"http://127.0.0.1:{server.server_address[1]}/"

    yield factory
    for server in servers:
        server.shutdown()
        server.server_close()


def make_self_signed_cert(tmp_path, not_before, not_after, name="cert"):
    """Write a self-signed cert/key pair for 127.0.0.1 and return (certfile, keyfile)."""
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "owasp-scanner-test")])
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
    return datetime.datetime.now(datetime.timezone.utc)


CERT_WINDOWS = {
    # expired since 2020, as in the SRS AT-10 verification
    "expired": lambda: (datetime.datetime(2019, 1, 1, tzinfo=datetime.timezone.utc),
                        datetime.datetime(2020, 1, 1, tzinfo=datetime.timezone.utc)),
    "valid": lambda: (_utcnow() - datetime.timedelta(days=1), _utcnow() + datetime.timedelta(days=365)),
    "expiring": lambda: (_utcnow() - datetime.timedelta(days=1), _utcnow() + datetime.timedelta(days=10)),
    "not_yet_valid": lambda: (_utcnow() + datetime.timedelta(days=10), _utcnow() + datetime.timedelta(days=400)),
}


@pytest.fixture
def https_server(tmp_path):
    """Factory: https_server(HandlerClass, cert="expired"|"valid"|...) -> (base URL, port).

    Serves HTTP over TLS with a self-signed certificate that the OS trust
    store does not know, so a verifying client always rejects it.
    """
    servers = []

    def factory(handler_cls, cert="valid"):
        not_before, not_after = CERT_WINDOWS[cert]()
        certfile, keyfile = make_self_signed_cert(tmp_path, not_before, not_after, name=cert)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile=str(certfile), keyfile=str(keyfile))
        server = ThreadingHTTPServer(("127.0.0.1", 0), handler_cls)
        server.socket = ctx.wrap_socket(server.socket, server_side=True)
        _start(server)
        servers.append(server)
        port = server.server_address[1]
        return f"https://127.0.0.1:{port}/", port

    yield factory
    for server in servers:
        server.shutdown()
        server.server_close()


@pytest.fixture
def closed_port():
    """A loopback port with nothing listening on it."""
    import socket

    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]
