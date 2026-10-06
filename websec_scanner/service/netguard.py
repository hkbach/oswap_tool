"""Which addresses a hosted scan may connect to (decision D12). Standard library only.

The service sends requests from the operator's machine to a URL an agency gave it, so an agency could ask it to scan the
operator's own internal network or a cloud metadata address. Two checks stop that:

* **At submission** (``check_target``): the target's name is resolved and every address it gives must be a public one.
  This answers the caller quickly, but a name can resolve differently a moment later.
* **At connection** (``is_public_address`` as a ``connect_guard`` of the scanning core): the address a socket really
  reached is checked before a byte is sent, for every connection, redirect and TLS handshake. This is the check that
  holds against DNS rebinding.

A public address is one ``ipaddress`` calls global, not multicast, not an IPv4 address in disguise (``::ffff:10.0.0.1``)
and not in a range that embeds an IPv4 address and could lead to a private one (NAT64, 6to4, Teredo).
"""

from __future__ import annotations

import ipaddress
import socket
import threading
from collections.abc import Callable
from urllib.parse import urlsplit

DNS_TIMEOUT_SECONDS = 5.0

# Ranges that carry an IPv4 address inside an IPv6 one; a gateway may turn them into a connection to a private host.
_EMBEDDING = tuple(ipaddress.ip_network(net) for net in ("64:ff9b::/96", "64:ff9b:1::/48", "2002::/16", "2001::/32"))


class TargetError(Exception):
    """A target the service will not scan. ``code`` is the stable error code of the API."""

    code = "target_not_allowed"
    detail = "The target is not one this service scans."


class TargetNotAllowed(TargetError):
    code = "target_not_allowed"
    detail = "The target resolves to an address this service does not scan (not a public internet address)."


class TargetUnresolvable(TargetError):
    code = "target_unresolvable"
    detail = "The target's host name could not be resolved."


def is_public_address(ip: str) -> bool:
    """True when ``ip`` is a public internet address that a scan may connect to."""
    try:
        address = ipaddress.ip_address(ip)  # an IPv6 scope id ("fe80::1%12") is understood by ipaddress itself
    except ValueError:
        return False
    if isinstance(address, ipaddress.IPv6Address):
        if address.ipv4_mapped is not None:
            address = address.ipv4_mapped  # judge the IPv4 address it stands for
        elif any(address in net for net in _EMBEDDING):
            return False
    return address.is_global and not address.is_multicast


def make_guard(allow_private: bool) -> Callable[[str], bool] | None:
    """The ``connect_guard`` for the scanning core, or None when the operator allows private targets (development)."""
    return None if allow_private else is_public_address


def _resolve(host: str, port: int, resolver: Callable, timeout: float) -> list[str]:
    """Addresses of ``host``, giving up after ``timeout`` seconds (a resolver cannot be stopped, so it runs aside)."""
    outcome: dict = {}

    def work() -> None:
        try:
            outcome["infos"] = resolver(host, port, type=socket.SOCK_STREAM)
        except (OSError, UnicodeError) as exc:  # gaierror, and a name too long or malformed for the IDNA codec
            outcome["error"] = exc

    thread = threading.Thread(target=work, daemon=True)
    thread.start()
    thread.join(timeout)
    if "infos" not in outcome:  # no answer in time (the resolver is still running), or it failed
        raise TargetUnresolvable
    return [str(info[4][0]) for info in outcome["infos"]]


def check_target(
    url: str, *, resolver: Callable = socket.getaddrinfo, timeout: float = DNS_TIMEOUT_SECONDS
) -> list[str]:
    """The addresses ``url`` resolves to, if every one of them is public; otherwise ``TargetError``.

    ``url`` is already normalised (an http:// or https:// URL). A host written as an address, in any of the forms an
    operating system accepts (``2130706433``, ``0x7f.1``, ``[::1]``), is judged by the address it stands for.
    """
    parts = urlsplit(url)
    host = parts.hostname
    if not host:
        raise TargetError
    try:
        port = parts.port or (443 if parts.scheme == "https" else 80)
    except ValueError:
        raise TargetError from None
    addresses = _resolve(host, port, resolver, timeout)
    if not addresses:
        raise TargetUnresolvable
    if not all(is_public_address(address) for address in addresses):
        raise TargetNotAllowed  # one internal address among public ones is enough: the scan could pick it
    return addresses


def has_userinfo(target: str) -> bool:
    """True for ``user:password@host`` or ``token@host``, with or without a scheme: no credential goes in a target."""
    text = target.strip()
    if "://" not in text:
        text = "https://" + text  # the scheme a bare host name gets, so what precedes the @ is not read as one
    try:
        return "@" in urlsplit(text).netloc
    except ValueError:
        return False
