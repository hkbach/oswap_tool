"""Local web UI: enter a URL, click Scan, see the findings below the form.

Usage:
    python -m owasp_scanner.web                # http://127.0.0.1:8765/
    python -m owasp_scanner.web --port 9000

After a scan, the page offers a "Download Test result" link: a standalone HTML
report (see html_report.py) kept in memory for the most recent scans only.

The UI runs the same run_scan() as the CLI. The authorization rule is the same
too: a scan only starts when the operator ticks the confirmation box, and the
API enforces that server-side. The server binds to loopback by default so other
machines cannot use it as an open scanner, and it rejects requests whose Host or
Origin is not this server (DNS-rebinding / cross-site request protection).
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
import secrets
import sys
import threading
from collections import OrderedDict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

from . import catalog
from .cli import _ca_bundle, _normalize_target, run_scan
from .html_report import render_html
from .output import DEFAULT_FAIL_ON, FAIL_ON_CHOICES, build_report, gate_message, group_findings, owasp_groups
from .redact import redact

_STATIC_DIR = Path(__file__).with_name("static")
_STATIC_FILES = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/app.js": ("app.js", "text/javascript; charset=utf-8"),
    "/app.css": ("app.css", "text/css; charset=utf-8"),
}
_MAX_BODY_BYTES = 4096
_MAX_DRAIN_BYTES = 65536  # how much of an oversized body we read before replying 413
_MAX_STORED_REPORTS = 20
# Fields the Web UI adds to the report dict of output.build_report() (SRS 6.3); everything else
# is the same JSON as the CLI's --json.
WEB_ONLY_FIELDS = (
    "gate_failed",
    "gate_status",
    "gate_message",
    "groups",
    "owasp_groups",
    "report_id",
    "report_url",
)
_REPORT_PATH = re.compile(r"^/api/report/([A-Za-z0-9_-]{16,64})\.html$")
_SECURITY_HEADERS = {
    "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
}


def _hostname(host_header: str) -> str:
    return (urlsplit("//" + host_header).hostname or "").lower()


def _is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host.strip("[]")).is_loopback
    except ValueError:
        return False


def _report_filename(report: dict) -> str:
    # Host and port only: never the userinfo part of the target (credentials).
    parts = urlsplit(report.get("target", ""))
    host = (parts.hostname or "target") + (f":{parts.port}" if parts.port else "")
    stamp = re.sub(r"\D", "", report.get("started_at", ""))[:14] or "report"
    return f"owasp-scan-{re.sub(r'[^A-Za-z0-9.-]', '_', host)}-{stamp}.html"


class ScanUIHandler(BaseHTTPRequestHandler):
    server_version = "OWASPScannerUI"

    # --- helpers -----------------------------------------------------------------

    def _send(self, status: int, body: bytes, content_type: str, extra_headers: dict | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        for name, value in {**_SECURITY_HEADERS, **(extra_headers or {})}.items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)

    def _json(self, status: int, payload: dict) -> None:
        self._send(status, json.dumps(payload, ensure_ascii=False).encode("utf-8"), "application/json; charset=utf-8")

    def _error(self, status: int, message: str) -> None:
        self._json(status, {"error": message})

    def _host_allowed(self) -> bool:
        # When bound to loopback, only loopback Host names are valid; anything else
        # means a DNS-rebinding page is talking to us through the browser.
        if not self.server.loopback_only:
            return True
        return _is_loopback(_hostname(self.headers.get("Host", "")))

    def _same_origin(self) -> bool:
        origin = self.headers.get("Origin")
        return origin is None or urlsplit(origin).netloc.lower() == self.headers.get("Host", "").lower()

    # --- routes ------------------------------------------------------------------

    def do_GET(self):
        if not self._host_allowed():
            return self._error(403, "Host not allowed")
        if self.path.split("?", 1)[0] == "/api/checks":
            groups = [{"id": g.id, "title": g.title, "description": g.description} for g in catalog.CHECK_GROUPS]
            return self._json(200, {"groups": groups})
        report_match = _REPORT_PATH.match(self.path)
        if report_match:
            return self._send_report(report_match.group(1))
        static = _STATIC_FILES.get(self.path.split("?", 1)[0])
        if static is None:
            return self._error(404, "Not found")
        filename, content_type = static
        self._send(200, (_STATIC_DIR / filename).read_bytes(), content_type)

    def do_POST(self):
        # Read the (bounded) body before any early error response: replying and closing
        # with unread request data makes some TCP stacks (Windows) reset the connection,
        # so the client never sees the status code.
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            return self._error(400, "Invalid Content-Length")
        if length < 0:
            return self._error(400, "Invalid Content-Length")
        if length > _MAX_BODY_BYTES:
            self.rfile.read(min(length, _MAX_DRAIN_BYTES))
            self.close_connection = True
            return self._error(413, "Request body too large")
        body = self.rfile.read(length)

        if self.path != "/api/scan":
            return self._error(404, "Not found")
        if not self._host_allowed() or not self._same_origin():
            return self._error(403, "Cross-origin requests are not allowed")
        # Requiring JSON forces a CORS preflight for any cross-site caller, which we never approve.
        if self.headers.get("Content-Type", "").split(";")[0].strip().lower() != "application/json":
            return self._error(415, "Content-Type must be application/json")
        try:
            payload = json.loads(body or b"{}")
        except ValueError:
            return self._error(400, "Body is not valid JSON")
        if not isinstance(payload, dict):
            return self._error(400, "Body must be a JSON object")

        if payload.get("authorized") is not True:
            return self._error(400, "Authorization not confirmed: only scan systems you own or are authorized to test.")
        raw_target = payload.get("target")
        if not isinstance(raw_target, str) or not raw_target.strip():
            return self._error(400, "Enter a target URL or hostname")
        target = _normalize_target(raw_target.strip())
        parts = urlsplit(target)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            return self._error(400, "Target must be an http:// or https:// URL")
        groups = None  # absent: every group, as in the CLI
        if "checks" in payload:
            checks = payload["checks"]
            if not isinstance(checks, list) or not all(isinstance(c, str) for c in checks):
                return self._error(400, "checks must be a list of check group ids")
            try:
                groups = catalog.normalize_groups(checks)
            except ValueError as exc:
                return self._error(400, str(exc))

        # One scan at a time keeps the load on the target bounded (NFR-PERF-02).
        if not self.server.scan_lock.acquire(blocking=False):
            return self._error(429, "A scan is already running; wait for it to finish")
        try:
            result = run_scan(
                target,
                timeout=self.server.scan_timeout,
                workers=self.server.scan_workers,
                ca_bundle=self.server.scan_ca_bundle,
                groups=groups,
            )
            report = build_report(result, fail_on=self.server.scan_fail_on)  # same pipeline as the CLI (FR-WEB-01)
        except Exception as exc:  # a bug must still answer the browser instead of dropping the connection
            # One redacted line on the server console; the message can contain the target URL.
            print(f"Scan failed: {type(exc).__name__}: {redact(str(exc))}", file=sys.stderr)
            return self._error(500, "The scan failed with an internal error; see the server console for details.")
        finally:
            self.server.scan_lock.release()

        report_id = self._store_report(report)
        data = dict(report, report_id=report_id, report_url=f"/api/report/{report_id}.html")
        data["gate_failed"] = report["gate"]["failed"]
        data["gate_status"], data["gate_message"] = gate_message(report["gate"])  # same text as the HTML report
        data["groups"], data["owasp_groups"] = group_findings(report), owasp_groups(report)  # same as the HTML report
        self._json(200, data)

    # --- stored reports ----------------------------------------------------------

    def _store_report(self, report: dict) -> str:
        # Unguessable id; only the most recent scans are kept, in memory only.
        report_id = secrets.token_urlsafe(16)
        with self.server.reports_lock:
            self.server.reports[report_id] = report
            while len(self.server.reports) > _MAX_STORED_REPORTS:
                self.server.reports.popitem(last=False)
        return report_id

    def _send_report(self, report_id: str) -> None:
        with self.server.reports_lock:
            report = self.server.reports.get(report_id)
        if report is None:
            return self._error(
                404, f"Report not found. Only the last {_MAX_STORED_REPORTS} scans are kept; run the scan again."
            )
        self._send(
            200,
            render_html(report).encode("utf-8"),
            "text/html; charset=utf-8",
            {"Content-Disposition": f'attachment; filename="{_report_filename(report)}"'},
        )


def build_server(
    host: str = "127.0.0.1",
    port: int = 8765,
    timeout: int = 10,
    workers: int = 5,
    ca_bundle: str | None = None,
    fail_on: str = DEFAULT_FAIL_ON,
) -> ThreadingHTTPServer:
    server = ThreadingHTTPServer((host, port), ScanUIHandler)
    server.loopback_only = _is_loopback(host)
    server.scan_lock = threading.Lock()
    server.scan_timeout = timeout
    server.scan_workers = workers
    server.scan_ca_bundle = ca_bundle
    server.scan_fail_on = fail_on
    server.reports = OrderedDict()
    server.reports_lock = threading.Lock()
    return server


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="owasp-scanner-web",
        description="Local web UI for the OWASP-aligned non-intrusive web security scanner.",
    )
    parser.add_argument("--host", default="127.0.0.1", help="Interface to bind (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8765, help="Port to listen on (default: 8765)")
    parser.add_argument("--timeout", type=int, default=10, help="Per-request timeout in seconds (default: 10)")
    parser.add_argument("--workers", type=int, default=5, help="Concurrent requests for path checks (default: 5)")
    parser.add_argument(
        "--fail-on",
        choices=FAIL_ON_CHOICES,
        default=DEFAULT_FAIL_ON,
        help="Lowest severity shown as a failed gate, as for the CLI (default: high)",
    )
    parser.add_argument(
        "--ca-bundle",
        metavar="PATH",
        type=_ca_bundle,
        help="PEM file of CA certificates to trust instead of the OS store (default: env, else OS store)",
    )
    args = parser.parse_args(argv)

    server = build_server(args.host, args.port, args.timeout, args.workers, args.ca_bundle, args.fail_on)
    if not server.loopback_only:
        print(
            f"WARNING: listening on {args.host}; anyone who can reach this port can start scans "
            "from this machine. Use the default 127.0.0.1 unless you really need remote access.",
            flush=True,
        )
    print(f"OWASP scanner UI running at http://{args.host}:{server.server_address[1]}/  (Ctrl+C to stop)", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
