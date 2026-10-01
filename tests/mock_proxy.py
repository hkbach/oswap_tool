"""A minimal local forward proxy for tests: absolute-URI GET for http:// and CONNECT for TLS.

Loopback only. It records what passed through it, so a test can prove that traffic (the TLS
check's handshakes included) really went via the proxy instead of connecting directly.
"""

from __future__ import annotations

import http.client
import select
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit


class ProxyHandler(BaseHTTPRequestHandler):
    seen: list[tuple[str, str]] = []  # (method, target) in arrival order
    proxy_auth: list[str | None] = []

    def log_message(self, format, *args):
        pass

    def _record(self) -> None:
        type(self).seen.append((self.command, self.path))
        type(self).proxy_auth.append(self.headers.get("Proxy-Authorization"))

    def do_GET(self):
        # http:// through a proxy: the request line carries the absolute URI.
        self._record()
        target = urlsplit(self.path)
        conn = http.client.HTTPConnection(target.hostname, target.port or 80, timeout=10)
        path = target.path or "/"
        if target.query:
            path += "?" + target.query
        headers = {
            k: v for k, v in self.headers.items() if k.lower() not in ("proxy-authorization", "proxy-connection")
        }
        conn.request("GET", path, headers=headers)
        resp = conn.getresponse()
        body = resp.read()
        self.send_response(resp.status)
        for k, v in resp.getheaders():
            if k.lower() not in ("transfer-encoding", "connection", "content-length"):
                self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
        conn.close()

    def do_CONNECT(self):
        self._record()
        host, _, port = self.path.rpartition(":")
        try:
            upstream = socket.create_connection((host.strip("[]"), int(port)), timeout=10)
        except OSError:
            self.send_error(502)
            return
        self.send_response(200, "Connection established")
        self.end_headers()
        self._relay(self.connection, upstream)

    @staticmethod
    def _relay(a: socket.socket, b: socket.socket) -> None:
        sockets = [a, b]
        try:
            while True:
                readable, _, broken = select.select(sockets, [], sockets, 10)
                if broken or not readable:
                    return
                for sock in readable:
                    data = sock.recv(65536)
                    if not data:
                        return
                    (b if sock is a else a).sendall(data)
        except OSError:
            return
        finally:
            b.close()


def start_proxy() -> tuple[ThreadingHTTPServer, str]:
    ProxyHandler.seen = []
    ProxyHandler.proxy_auth = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), ProxyHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, f"http://127.0.0.1:{server.server_address[1]}"
