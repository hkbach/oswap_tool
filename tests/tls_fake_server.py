"""A protocol-level fake TLS server for the probing tests (FR-DET-04, decision D7).

OpenSSL on a developer machine cannot speak SSLv3 or serve RC4/EXPORT suites, so a test built on a
real server would skip exactly where the probes matter. This server reads a ClientHello with its own
strict parser and answers with a hand-built ServerHello or an alert, according to a policy. It
completes no handshake: like the scanner's probes, it stops after the first reply.

The parser here is written separately from the scanner's builder on purpose: if both shared one
misreading of the RFC, a test between them would pass while a real server rejected the probe.
tests/test_tls_probe.py also checks both against real OpenSSL.

It records every connection, every ClientHello and any bytes the client sends after the hello, so a
test can prove how many connections a probe run opened and that it sent exactly one record.
"""

from __future__ import annotations

import os
import socket
import socketserver
import struct
import threading
from dataclasses import dataclass, field

SCSV = 0x00FF  # TLS_EMPTY_RENEGOTIATION_INFO_SCSV: a signalling value, never a real suite
ALERT_FATAL = 2
ALERT_HANDSHAKE_FAILURE = 40
ALERT_PROTOCOL_VERSION = 70
HELLO_RETRY_REQUEST_RANDOM = bytes.fromhex(
    "CF21AD74E59A6111BE1D8C021E65B891C2A211167ABB8C5E079E09E2C8A8339C"
)  # RFC 8446 4.1.3

EXT_SERVER_NAME = 0
EXT_SUPPORTED_GROUPS = 10
EXT_EC_POINT_FORMATS = 11
EXT_SIGNATURE_ALGORITHMS = 13
EXT_SUPPORTED_VERSIONS = 43
EXT_KEY_SHARE = 51


def u16(data: bytes) -> int:
    return struct.unpack("!H", data)[0]


@dataclass
class ClientHello:
    record_version: int
    client_version: int
    random: bytes
    session_id: bytes
    suites: list[int]
    compression: bytes
    extensions: dict[int, bytes]
    raw: bytes  # the whole record as received

    @property
    def sni(self) -> str | None:
        data = self.extensions.get(EXT_SERVER_NAME)
        if data is None:
            return None
        list_len = u16(data[:2])
        assert list_len == len(data) - 2, "server_name list length"
        assert data[2] == 0, "server_name type must be host_name"
        name_len = u16(data[3:5])
        assert name_len == len(data) - 5, "server_name length"
        return data[5:].decode("ascii")

    def _u16_list(self, ext: int) -> list[int] | None:
        data = self.extensions.get(ext)
        if data is None:
            return None
        return [u16(data[i : i + 2]) for i in range(2, len(data), 2)]

    @property
    def supported_versions(self) -> list[int] | None:
        data = self.extensions.get(EXT_SUPPORTED_VERSIONS)
        if data is None:
            return None
        assert data[0] == len(data) - 1, "supported_versions length"
        return [u16(data[i : i + 2]) for i in range(1, len(data), 2)]

    @property
    def supported_groups(self) -> list[int] | None:
        return self._u16_list(EXT_SUPPORTED_GROUPS)

    @property
    def signature_algorithms(self) -> list[int] | None:
        return self._u16_list(EXT_SIGNATURE_ALGORITHMS)

    @property
    def key_shares(self) -> list[tuple[int, bytes]] | None:
        data = self.extensions.get(EXT_KEY_SHARE)
        if data is None:
            return None
        assert u16(data[:2]) == len(data) - 2, "key_share length"
        shares, pos = [], 2
        while pos < len(data):
            group, size = u16(data[pos : pos + 2]), u16(data[pos + 2 : pos + 4])
            shares.append((group, data[pos + 4 : pos + 4 + size]))
            pos += 4 + size
        return shares


def parse_client_hello(record: bytes) -> ClientHello:
    """Strict: every length field must add up exactly, or the hello is malformed."""
    if len(record) < 5 or record[0] != 22:
        raise ValueError("not a handshake record")
    length = u16(record[3:5])
    body = record[5 : 5 + length]
    if len(body) != length or len(record) != 5 + length:
        raise ValueError("record length mismatch")
    if body[0] != 1:
        raise ValueError("not a ClientHello")
    hello_len = int.from_bytes(body[1:4], "big")
    hello = body[4 : 4 + hello_len]
    if len(hello) != hello_len or 4 + hello_len != len(body):
        raise ValueError("handshake length mismatch")

    client_version, random, sid_len = u16(hello[0:2]), hello[2:34], hello[34]
    pos = 35 + sid_len
    session_id = hello[35:pos]
    suites_len = u16(hello[pos : pos + 2])
    pos += 2
    if suites_len == 0 or suites_len % 2:
        raise ValueError("bad cipher suite list length")
    suites = [u16(hello[pos + i : pos + i + 2]) for i in range(0, suites_len, 2)]
    pos += suites_len
    comp_len = hello[pos]
    compression = hello[pos + 1 : pos + 1 + comp_len]
    pos += 1 + comp_len

    extensions: dict[int, bytes] = {}
    if pos < len(hello):
        total = u16(hello[pos : pos + 2])
        pos += 2
        if pos + total != len(hello):
            raise ValueError("extensions length mismatch")
        while pos < len(hello):
            ext_type, ext_len = u16(hello[pos : pos + 2]), u16(hello[pos + 2 : pos + 4])
            if ext_type in extensions:
                raise ValueError(f"duplicate extension {ext_type}")
            extensions[ext_type] = hello[pos + 4 : pos + 4 + ext_len]
            if len(extensions[ext_type]) != ext_len:
                raise ValueError("extension runs past the hello")
            pos += 4 + ext_len
    return ClientHello(u16(record[1:3]), client_version, random, session_id, suites, compression, extensions, record)


def server_hello(version: int, suite: int, *, tls13: bool = False, random: bytes | None = None) -> bytes:
    """One handshake record holding a ServerHello. TLS 1.3 shows its version in an extension."""
    body = (
        struct.pack("!H", 0x0303 if tls13 else version)
        + (random or os.urandom(32))
        + b"\x00"
        + struct.pack("!H", suite)
        + b"\x00"
    )
    if tls13:
        extensions = struct.pack("!HHH", EXT_SUPPORTED_VERSIONS, 2, 0x0304)
        extensions += struct.pack("!HHH", EXT_KEY_SHARE, 36, 0x001D) + struct.pack("!H", 32) + os.urandom(32)
        body += struct.pack("!H", len(extensions)) + extensions
    handshake = b"\x02" + len(body).to_bytes(3, "big") + body
    return b"\x16" + struct.pack("!HH", 0x0303 if tls13 else version, len(handshake)) + handshake


def alert(version: int, description: int, level: int = ALERT_FATAL) -> bytes:
    return b"\x15" + struct.pack("!HH", version, 2) + bytes([level, description])


@dataclass
class Policy:
    """What the fake server speaks. ``versions`` are protocol codes (0x0301 is TLS 1.0)."""

    versions: set[int] = field(default_factory=lambda: {0x0303})
    suites: set[int] | None = None  # None: any suite the client offers
    force_suite: int | None = None  # a misbehaving server: answers with this suite, offered or not
    behaviour: str = "normal"  # normal | close | reset | silent | http | split | garbage-length


def _recv_exact(conn: socket.socket, size: int) -> bytes:
    data = b""
    while len(data) < size:
        chunk = conn.recv(size - len(data))
        if not chunk:
            raise ConnectionError("peer closed")
        data += chunk
    return data


class _Handler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        server: FakeTlsServer = self.server.owner  # type: ignore[attr-defined]
        conn: socket.socket = self.request
        conn.settimeout(3)
        with server.lock:
            server.connections += 1
        try:
            header = _recv_exact(conn, 5)
            record = header + _recv_exact(conn, u16(header[3:5]))
            hello = parse_client_hello(record)
        except (OSError, ValueError, AssertionError) as exc:
            with server.lock:
                server.errors.append(f"bad ClientHello: {exc}")
            return
        with server.lock:
            server.hellos.append(hello)
        try:
            self._answer(server, conn, hello)
            self._watch_for_extra_bytes(server, conn)
        except OSError:
            pass

    def _answer(self, server: FakeTlsServer, conn: socket.socket, hello: ClientHello) -> None:
        behaviour = server.policy.behaviour
        if behaviour == "close":
            return
        if behaviour == "reset":
            conn.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
            return
        if behaviour == "silent":
            conn.settimeout(5)
            try:
                conn.recv(1)  # hold the connection open until the client gives up
            except OSError:
                pass
            return
        if behaviour == "http":
            conn.sendall(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
            return
        if behaviour == "garbage-length":
            conn.sendall(b"\x16\x03\x03\xff\xff" + b"\x00" * 16)
            return
        reply = server.reply_for(hello)
        if behaviour == "split":
            for i in range(0, len(reply), 3):
                conn.sendall(reply[i : i + 3])
                threading.Event().wait(0.01)
            return
        conn.sendall(reply)

    def _watch_for_extra_bytes(self, server: FakeTlsServer, conn: socket.socket) -> None:
        """Anything the client writes after its ClientHello is recorded: probes must send none."""
        conn.settimeout(0.4)
        try:
            extra = conn.recv(4096)
        except OSError:
            return
        if extra:
            with server.lock:
                server.extra_bytes.append(extra)


class _Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class FakeTlsServer:
    def __init__(self, policy: Policy | None = None) -> None:
        self.policy = policy or Policy()
        self.lock = threading.Lock()
        self.connections = 0
        self.hellos: list[ClientHello] = []
        self.extra_bytes: list[bytes] = []
        self.errors: list[str] = []
        self._server = _Server(("127.0.0.1", 0), _Handler)
        self._server.owner = self  # type: ignore[attr-defined]
        self.port: int = self._server.server_address[1]
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    def __enter__(self) -> FakeTlsServer:
        self._thread.start()
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def close(self) -> None:
        self._server.shutdown()
        self._server.server_close()

    def reply_for(self, hello: ClientHello) -> bytes:
        """Choose a version and a suite the way a server would, or answer with an alert."""
        offered = hello.supported_versions
        if offered is not None and 0x0304 in offered and 0x0304 in self.policy.versions:
            suites = [s for s in hello.suites if 0x1301 <= s <= 0x1305 and self._allows(s)]
            if suites:
                return server_hello(0x0303, suites[0], tls13=True)
            return alert(0x0303, ALERT_HANDSHAKE_FAILURE)
        ceiling = hello.client_version if offered is None else max((v for v in offered if v != 0x0304), default=0)
        usable = sorted(v for v in self.policy.versions if v <= ceiling and v != 0x0304)
        if not usable:
            return alert(hello.record_version, ALERT_PROTOCOL_VERSION)
        version = usable[-1]
        if self.policy.force_suite is not None:
            return server_hello(version, self.policy.force_suite)
        suites = [s for s in hello.suites if s != SCSV and not 0x1301 <= s <= 0x1305 and self._allows(s)]
        if not suites:
            return alert(version, ALERT_HANDSHAKE_FAILURE)
        return server_hello(version, suites[0])

    def _allows(self, suite: int) -> bool:
        return self.policy.suites is None or suite in self.policy.suites
