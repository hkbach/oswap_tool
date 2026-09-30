"""A tiny mock web server with deliberately mixed-quality security config,
used only to exercise the scanner's HTTP-based checks end-to-end offline
(TLS/HTTPS-only checks are naturally skipped when scanning plain http://).
"""
from __future__ import annotations

import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class Handler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):  # silence default access log
        pass

    def _send(self, status, body=b"", headers=None):
        self.send_response(status)
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if body:
            self.wfile.write(body)

    def do_GET(self):
        path = self.path.split("?")[0]

        if path == "/":
            self._send(
                200,
                b"<html><body>Mock target OK</body></html>",
                {
                    "Content-Type": "text/html",
                    # Intentionally missing CSP, X-Frame-Options, Referrer-Policy, Permissions-Policy
                    "X-Content-Type-Options": "nosniff",
                    "Server": "Apache/2.2.15 (CentOS)",
                    "X-Powered-By": "PHP/5.6.40",
                    "Set-Cookie": "session=abc123; Path=/",  # missing Secure/HttpOnly/SameSite
                },
            )
        elif path == "/robots.txt":
            self._send(200, b"User-agent: *\nDisallow: /admin/\nDisallow: /backup/\n", {"Content-Type": "text/plain"})
        elif path == "/.git/HEAD":
            self._send(200, b"ref: refs/heads/master\n", {"Content-Type": "text/plain"})
        elif path == "/.env":
            self._send(200, b"DB_PASSWORD=hunter2\n", {"Content-Type": "text/plain"})
        elif path == "/images/":
            self._send(200, b"<html><title>Index of /images</title><body>Index of /images/</body></html>", {"Content-Type": "text/html"})
        elif path.startswith("/owasp-scanner-nonexistent-probe"):
            self._send(404, b"Not Found")
        else:
            self._send(404, b"Not Found")


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8899
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    print(f"Mock server listening on http://127.0.0.1:{port}")
    server.serve_forever()


if __name__ == "__main__":
    main()
