"""Active TLS probing: which protocol versions and weak cipher groups a server accepts (FR-DET-04, D7).

The certificate check asks the server for one protocol and one cipher, so a server that offers
TLS 1.2 *and* TLS 1.0 is reported as fine. A probe asks the other question: it offers exactly one
protocol version, or exactly one group of weak cipher suites, and sees whether the server agrees.

What a probe is, and is not
---------------------------
* One TCP connection, one TLS record: a standard ClientHello that a browser-like client could
  send. The scanner reads the server's first reply (a ServerHello, or an alert) and closes.
  No handshake is completed and no application data is sent: nothing is exploited, nothing is
  negotiated beyond the hello, nothing malformed is sent.
* The hello is built here with ``socket`` and ``struct`` rather than with OpenSSL, because a
  current OpenSSL cannot offer SSLv3 or export suites at all, and a probe has to be able to ask.
* Every probe is a connection: it goes through the limiter and the proxy like any other request,
  waits a fraction of a second after the previous one, and is capped by a per-run budget.
* "Not enabled" is only ever claimed from the server's own answer (an alert, or a hang-up after
  the hello). A server that could not be reached, or never answered, is an ``ERROR``: the caller
  reports "could not test", never a silent pass.

SSLv2 is not probed: it uses a different hello format and no current server speaks it.
The data (versions, suite codes, limits) is in ``rules/tls_probe.json``.
"""

from __future__ import annotations

import enum
import ipaddress
import os
import socket
import struct
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field

from ..http_utils import url_host
from ..rule_loader import CipherGroup, ProtocolProbe, TlsProbeRules

_RECORD_ALERT, _RECORD_HANDSHAKE = 21, 22
_TLS_RECORD_TYPES = (20, 21, 22, 23)
_CLIENT_HELLO, _SERVER_HELLO = 1, 2
_SCSV = 0x00FF  # TLS_EMPTY_RENEGOTIATION_INFO_SCSV: tells the server this client knows secure renegotiation
_MAX_RECORD = 16384 + 2048  # the TLS plaintext limit plus the expansion RFC 8446 allows
_MAX_REPLY_RECORDS = 3  # a ServerHello normally arrives in the first
_CERTIFICATE_CONNECTIONS = 2  # kept free for the certificate read and the trust check

_VERSION_NAMES = {0x0300: "SSLv3", 0x0301: "TLSv1", 0x0302: "TLSv1.1", 0x0303: "TLSv1.2", 0x0304: "TLSv1.3"}
_ALERT_NAMES = {
    0: "close_notify", 10: "unexpected_message", 20: "bad_record_mac", 22: "record_overflow",
    30: "decompression_failure", 40: "handshake_failure", 41: "no_certificate", 42: "bad_certificate",
    43: "unsupported_certificate", 44: "certificate_revoked", 45: "certificate_expired",
    46: "certificate_unknown", 47: "illegal_parameter", 48: "unknown_ca", 49: "access_denied",
    50: "decode_error", 51: "decrypt_error", 60: "export_restriction", 70: "protocol_version",
    71: "insufficient_security", 80: "internal_error", 86: "inappropriate_fallback", 90: "user_canceled",
    100: "no_renegotiation", 109: "missing_extension", 110: "unsupported_extension",
    112: "unrecognized_name", 120: "no_application_protocol",
}  # fmt: skip

_EXT_SERVER_NAME, _EXT_SUPPORTED_GROUPS, _EXT_EC_POINT_FORMATS = 0, 10, 11
_EXT_SIGNATURE_ALGORITHMS, _EXT_SUPPORTED_VERSIONS, _EXT_KEY_SHARE = 13, 43, 51
_GROUPS = (0x001D, 0x0017, 0x0018, 0x0019)  # x25519, secp256r1, secp384r1, secp521r1
_SIGNATURE_ALGORITHMS = (0x0804, 0x0805, 0x0806, 0x0403, 0x0503, 0x0603, 0x0401, 0x0501, 0x0601, 0x0201, 0x0203)

_sleep = time.sleep  # looked up at call time, so a test can replace the pause


class Outcome(enum.Enum):
    ACCEPTED = "accepted"  # the server answered with a ServerHello for what was offered
    REJECTED = "rejected"  # an alert, or a hang-up after the hello: the server refuses it
    ERROR = "error"  # could not be tested: unreachable, silent, or not TLS


@dataclass(frozen=True)
class ProbeResult:
    outcome: Outcome
    protocol: str | None = None  # the version the ServerHello selected
    suite: int | None = None  # the suite the ServerHello selected
    detail: str = ""  # why a probe was rejected or could not run


@dataclass
class ProbeReport:
    protocols: dict[str, ProbeResult] = field(default_factory=dict)  # by protocol name, in rule order
    groups: dict[str, ProbeResult] = field(default_factory=dict)  # by group id, in rule order
    connections: int = 0


# --- building the ClientHello ----------------------------------------------------------------------


def _u16(value: int) -> bytes:
    return struct.pack("!H", value)


def _extension(kind: int, data: bytes) -> bytes:
    return _u16(kind) + _u16(len(data)) + data


def _server_name(hostname: str) -> bytes | None:
    """The SNI extension for a host name; never for an IP address (RFC 6066) or an unencodable name."""
    host = hostname.strip().strip("[]").rstrip(".")
    try:
        ipaddress.ip_address(host)
        return None
    except ValueError:
        pass
    try:
        name = host.encode("idna").decode("ascii").lower().encode("ascii")
    except UnicodeError:
        return None
    if not name or len(name) > 255:
        return None
    entry = b"\x00" + _u16(len(name)) + name
    return _extension(_EXT_SERVER_NAME, _u16(len(entry)) + entry)


def _common_extensions(hostname: str, *, signature_algorithms: bool) -> list[bytes]:
    extensions = []
    name = _server_name(hostname)
    if name is not None:
        extensions.append(name)
    extensions.append(_extension(_EXT_SUPPORTED_GROUPS, _u16(2 * len(_GROUPS)) + b"".join(_u16(g) for g in _GROUPS)))
    extensions.append(_extension(_EXT_EC_POINT_FORMATS, b"\x01\x00"))  # uncompressed only
    if signature_algorithms:
        data = b"".join(_u16(a) for a in _SIGNATURE_ALGORITHMS)
        extensions.append(_extension(_EXT_SIGNATURE_ALGORITHMS, _u16(len(data)) + data))
    return extensions


def _client_hello(
    *,
    record_version: int,
    client_version: int,
    suites: Sequence[int],
    extensions: Sequence[bytes],
    session_id: bytes = b"",
    random_bytes: bytes | None = None,
) -> bytes:
    random = os.urandom(32) if random_bytes is None else random_bytes
    if len(random) != 32:
        raise ValueError("the ClientHello random must be 32 bytes")
    body = _u16(client_version) + random + bytes([len(session_id)]) + session_id
    body += _u16(2 * len(suites)) + b"".join(_u16(s) for s in suites) + b"\x01\x00"  # compression: null only
    if extensions:
        block = b"".join(extensions)
        body += _u16(len(block)) + block
    handshake = bytes([_CLIENT_HELLO]) + len(body).to_bytes(3, "big") + body
    return bytes([_RECORD_HANDSHAKE]) + _u16(record_version) + _u16(len(handshake)) + handshake


def protocol_hello(protocol: ProtocolProbe, hostname: str, *, random_bytes: bytes | None = None) -> bytes:
    """A ClientHello that offers exactly ``protocol`` and nothing newer or older."""
    version = protocol.version
    if version == 0x0304:
        # TLS 1.3 is offered through supported_versions; the legacy field says 1.2, as every 1.3 client does.
        extensions = _common_extensions(hostname, signature_algorithms=True)
        extensions = [e for e in extensions if e[:2] != _u16(_EXT_EC_POINT_FORMATS)]
        extensions.append(_extension(_EXT_SUPPORTED_VERSIONS, b"\x02" + _u16(0x0304)))
        share = _u16(0x001D) + _u16(32) + os.urandom(32)  # a well-formed x25519 value; no key is ever derived
        extensions.append(_extension(_EXT_KEY_SHARE, _u16(len(share)) + share))
        return _client_hello(
            record_version=0x0301,
            client_version=0x0303,
            suites=protocol.probe_suites,
            extensions=extensions,
            session_id=os.urandom(32),  # middlebox-compatibility mode
            random_bytes=random_bytes,
        )
    extensions = [] if version == 0x0300 else _common_extensions(hostname, signature_algorithms=version >= 0x0303)
    return _client_hello(
        record_version=0x0300 if version == 0x0300 else 0x0301,
        client_version=version,
        suites=[*protocol.probe_suites, _SCSV],
        extensions=extensions,
        random_bytes=random_bytes,
    )


def group_hello(group: CipherGroup, hostname: str, *, random_bytes: bytes | None = None) -> bytes:
    """A ClientHello that offers only the suites of one weak group, up to TLS 1.2."""
    return _client_hello(
        record_version=0x0301,
        client_version=0x0303,
        suites=[*(s.code for s in group.suites), _SCSV],
        extensions=_common_extensions(hostname, signature_algorithms=True),
        random_bytes=random_bytes,
    )


# --- reading the first reply ---------------------------------------------------------------------------


class _Closed(Exception):
    """The peer closed the connection; ``received`` bytes had arrived by then."""

    def __init__(self, received: int) -> None:
        super().__init__(received)
        self.received = received


class _Unreadable(Exception):
    """The reply is not a TLS reply we can read; the message says why."""


def _read_exactly(sock: socket.socket, size: int, received: list[int]) -> bytes:
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise _Closed(received[0])
        received[0] += len(chunk)
        data += chunk
    return data


def _parse_server_hello(handshake: bytes) -> ProbeResult | None:
    """The version and suite of a ServerHello, or None while more of it is still to come."""
    if len(handshake) < 4:
        return None
    if handshake[0] != _SERVER_HELLO:
        raise _Unreadable(f"unexpected handshake message type {handshake[0]} where a ServerHello belongs")
    size = int.from_bytes(handshake[1:4], "big")
    if len(handshake) < 4 + size:
        return None
    body = handshake[4 : 4 + size]
    if len(body) < 38:
        raise _Unreadable("the ServerHello is too short")
    version, session_id_length = struct.unpack("!H", body[:2])[0], body[34]
    if session_id_length > 32:
        raise _Unreadable("the ServerHello has an invalid session id length")
    position = 35 + session_id_length
    if len(body) < position + 3:
        raise _Unreadable("the ServerHello is too short")
    suite = struct.unpack("!H", body[position : position + 2])[0]
    position += 3  # the suite and the compression method
    if position < len(body):  # extensions: TLS 1.3 names its real version in supported_versions
        if (
            len(body) < position + 2
            or struct.unpack("!H", body[position : position + 2])[0] != len(body) - position - 2
        ):
            raise _Unreadable("the ServerHello extensions are malformed")
        position += 2
        while position < len(body):
            if len(body) < position + 4:
                raise _Unreadable("the ServerHello extensions are malformed")
            kind, length = struct.unpack("!HH", body[position : position + 4])
            data = body[position + 4 : position + 4 + length]
            if len(data) != length:
                raise _Unreadable("the ServerHello extensions are malformed")
            if kind == _EXT_SUPPORTED_VERSIONS and length == 2:
                version = struct.unpack("!H", data)[0]
            position += 4 + length
    name = _VERSION_NAMES.get(version)
    if name is None:
        raise _Unreadable(f"the server selected an unknown protocol version 0x{version:04x}")
    return ProbeResult(Outcome.ACCEPTED, protocol=name, suite=suite)


def _read(sock: socket.socket, received: list[int]) -> ProbeResult:
    handshake = b""
    for _ in range(_MAX_REPLY_RECORDS):
        header = _read_exactly(sock, 5, received)
        if header[0] not in _TLS_RECORD_TYPES or header[1] != 3:
            raise _Unreadable("the reply is not a TLS record: the port may not be speaking TLS")
        length = struct.unpack("!H", header[3:5])[0]
        if length == 0 or length > _MAX_RECORD:
            raise _Unreadable(f"the reply has an invalid TLS record length ({length})")
        payload = _read_exactly(sock, length, received)
        if header[0] == _RECORD_ALERT:
            if len(payload) < 2:
                raise _Unreadable("the TLS alert is truncated")
            name = _ALERT_NAMES.get(payload[1], f"alert {payload[1]}")
            return ProbeResult(Outcome.REJECTED, detail=f"the server answered with the alert {name}")
        if header[0] != _RECORD_HANDSHAKE:
            raise _Unreadable(f"unexpected TLS record type {header[0]} where a ServerHello belongs")
        handshake += payload
        result = _parse_server_hello(handshake)
        if result is not None:
            return result
    raise _Unreadable("the ServerHello did not fit in three records")


def read_reply(sock: socket.socket) -> ProbeResult:
    """Read the server's first reply to a ClientHello and classify it. Never raises on bad input."""
    received = [0]
    try:
        return _read(sock, received)
    except _Closed as closed:
        if closed.received == 0:
            return ProbeResult(Outcome.REJECTED, detail="the server closed the connection without a ServerHello")
        return ProbeResult(
            Outcome.ERROR, detail=f"the reply was truncated (the server closed after {closed.received} bytes)"
        )
    except _Unreadable as exc:
        return ProbeResult(Outcome.ERROR, detail=str(exc))
    except TimeoutError:
        timeout = sock.gettimeout()
        return ProbeResult(Outcome.ERROR, detail=f"no reply within {timeout:g}s" if timeout else "no reply")
    except (ConnectionResetError, ConnectionAbortedError):
        return ProbeResult(Outcome.REJECTED, detail="the server reset the connection")
    except OSError as exc:
        return ProbeResult(Outcome.ERROR, detail=str(exc))


# --- running the probes ----------------------------------------------------------------------------------


def _default_connect(hostname: str, port: int, timeout: float) -> socket.socket:
    return socket.create_connection((hostname, port), timeout=timeout)


def _probe_once(hello: bytes, hostname: str, port: int, timeout: float, connect: Callable) -> tuple[ProbeResult, bool]:
    """The result of one probe, and whether the TCP connection could be opened at all."""
    try:
        sock = connect(hostname, port, timeout)
    except OSError as exc:
        return ProbeResult(Outcome.ERROR, detail=f"could not connect: {exc}"), False
    with sock:
        try:
            sock.settimeout(timeout)
            sock.sendall(hello)
        except (ConnectionResetError, ConnectionAbortedError):
            return ProbeResult(Outcome.REJECTED, detail="the server reset the connection"), True
        except OSError as exc:
            return ProbeResult(Outcome.ERROR, detail=str(exc)), True
        return read_reply(sock), True


def _protocol_verdict(probe: ProtocolProbe, result: ProbeResult) -> ProbeResult:
    """A server may answer a hello for version X with a lower version it does support: X itself is then off."""
    if result.outcome is Outcome.ACCEPTED and result.protocol != probe.name:
        return ProbeResult(Outcome.REJECTED, detail=f"the server answered with {result.protocol} instead")
    return result


def _group_verdict(group: CipherGroup, result: ProbeResult) -> ProbeResult:
    if result.outcome is Outcome.ACCEPTED and result.suite not in {s.code for s in group.suites}:
        return ProbeResult(
            Outcome.ERROR, detail=f"the server selected 0x{result.suite or 0:04X}, which was not offered"
        )
    return result


def run_probes(
    hostname: str,
    port: int,
    timeout: float,
    rules: TlsProbeRules,
    *,
    connect: Callable[[str, int, float], socket.socket] | None = None,
    limiter=None,
    sleep: Callable[[float], None] | None = None,
) -> ProbeReport:
    """Probe every protocol version and weak cipher group in ``rules``, one connection each.

    ``connect`` opens the TCP connection (the TLS check passes one that honours --proxy). Each
    connection is announced to ``limiter``, so --rate-limit and --max-requests apply and
    ScanLimitReached propagates. The run is bounded by ``rules.max_connections`` (two connections
    are kept for the certificate checks), by a pause between connections, and by a per-probe
    timeout; a failure to connect stops the run, since every further probe would wait out the
    same timeout.
    """
    connect = connect or _default_connect
    pause = sleep if sleep is not None else _sleep
    budget = max(0, rules.max_connections - _CERTIFICATE_CONNECTIONS)
    probe_timeout = min(float(timeout), rules.probe_timeout_seconds)
    url = f"https://{url_host(hostname)}:{port}/"

    plan: list[tuple[dict, str, Callable[[], bytes], Callable[[ProbeResult], ProbeResult]]] = []
    report = ProbeReport()
    for protocol in rules.protocols:
        plan.append(
            (
                report.protocols,
                protocol.name,
                lambda p=protocol: protocol_hello(p, hostname),
                lambda r, p=protocol: _protocol_verdict(p, r),
            )
        )
    for group in rules.groups:
        if group.probed:
            plan.append(
                (
                    report.groups,
                    group.id,
                    lambda g=group: group_hello(g, hostname),
                    lambda r, g=group: _group_verdict(g, r),
                )
            )

    stopped = ""
    for results, key, build, verdict in plan:
        if stopped:
            results[key] = ProbeResult(Outcome.ERROR, detail=stopped)
            continue
        if report.connections >= budget:
            results[key] = ProbeResult(
                Outcome.ERROR, detail=f"not tested: the connection budget of {rules.max_connections} was reached"
            )
            continue
        if report.connections:
            pause(rules.pause_seconds)
        if limiter is not None:
            limiter.acquire(url)  # a probe is traffic too (FR-AUTHZ-05); a reached limit stops the scan
        report.connections += 1
        result, connected = _probe_once(build(), hostname, port, probe_timeout, connect)
        if not connected:
            stopped = f"not tested: {result.detail}"
        results[key] = verdict(result)
    return report
