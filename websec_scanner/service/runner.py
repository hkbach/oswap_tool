"""Runs queued scans in the background (decision D12).

The queue is the ``scans`` table (status ``queued``), so it survives a restart. ``pump()`` starts every queued scan that
the limits allow, oldest first: at most ``max_concurrent_scans`` at a time, ``max_concurrent_per_agency`` for one
agency,
and one at a time against the same host, so a few requests for one site cannot add up to a flood. Each scan runs in its
own daemon thread and ends by pumping again.

A scan that cannot even fetch the home page still *completes*: its report says so (``gate.incomplete``), exactly as the
CLI exits 3 with a report. ``failed`` is for a scan that broke inside the service, or was running when the service
stopped (``interrupted``).
"""

from __future__ import annotations

import json
import logging
import threading
import time
from collections import Counter
from collections.abc import Callable

from ..output import DEFAULT_FAIL_ON, build_report
from ..redact import redact
from . import netguard, storage
from .config import Settings
from .db import Repository

log = logging.getLogger("websec_scanner.service")


class ScanRunner:
    def __init__(
        self,
        settings: Settings,
        repo: Repository,
        scan_fn: Callable | None = None,
        connect_guard: Callable[[str], bool] | None | str = "default",
    ) -> None:
        if scan_fn is None:
            from ..cli import run_scan as scan_fn  # the scanning core, imported when a scan is first wanted
        self._settings, self._repo, self._scan_fn = settings, repo, scan_fn
        self._guard = (
            netguard.make_guard(settings.allow_private_targets) if connect_guard == "default" else connect_guard
        )
        self._lock = threading.Lock()
        self._running: dict[str, tuple[str, str]] = {}  # scan_id -> (agency_id, target_host)
        self._closed = False

    # --- starting scans -----------------------------------------------------------------------------

    def recover(self) -> int:
        """Fail the scans a stopped service left running, then start what was waiting. Returns how many failed."""
        failed = self._repo.recover_interrupted()
        self.pump()
        return failed

    def pump(self) -> None:
        """Start every queued scan the limits allow."""
        s = self._settings
        with self._lock:
            if self._closed:
                return
            hosts = {host for _, host in self._running.values()}
            per_agency = Counter(agency for agency, _ in self._running.values())
            for scan in self._repo.queued_scans():
                if len(self._running) >= s.max_concurrent_scans:
                    break
                scan_id, agency, host = scan["scan_id"], scan["agency_id"], scan["target_host"]
                if scan_id in self._running or per_agency[agency] >= s.max_concurrent_per_agency or host in hosts:
                    continue
                if not self._repo.mark_running(scan_id):
                    continue
                self._running[scan_id] = (agency, host)
                hosts.add(host)
                per_agency[agency] += 1
                try:
                    threading.Thread(target=self._work, args=(scan,), daemon=True, name=f"scan-{scan_id[-6:]}").start()
                except RuntimeError:  # no thread could be started: do not leave the scan "running" for nothing
                    del self._running[scan_id]
                    self._repo.fail_scan(scan_id, "scan_error")

    def close(self) -> None:
        """Start nothing more. Running scans are daemon threads: on exit they end and are failed at the next start."""
        with self._lock:
            self._closed = True

    # --- one scan -----------------------------------------------------------------------------------

    def _work(self, scan: dict) -> None:
        scan_id = scan["scan_id"]
        try:
            content, summary = self._scan_and_report(scan)
            path = storage.write_report(
                self._settings.results_dir, scan["agency_id"], scan["client_id"], scan_id, content
            )
            self._repo.finish_scan(scan_id, summary, path)
        except Exception as exc:  # any failure of one scan must leave the service, and the other scans, running
            # The text can hold the target URL, which may carry a token of the agency's own: redact it like any output.
            log.error("scan %s failed: %s: %s", scan_id, type(exc).__name__, redact(str(exc)))
            self._repo.fail_scan(scan_id, "scan_error")
        finally:
            with self._lock:
                self._running.pop(scan_id, None)
            self.pump()

    def _scan_and_report(self, scan: dict) -> tuple[bytes, dict]:
        s = self._settings
        result = self._scan_fn(
            scan["target"],
            timeout=s.scan_timeout,
            workers=s.scan_workers,
            groups=scan["checks"],
            rate_limit=s.scan_rate_limit,
            max_requests=s.scan_max_requests,
            max_duration=s.scan_max_duration,
            tls_probe=s.tls_probe,
            crawl=s.crawl if scan["crawl"] else None,
            connect_guard=self._guard,
        )
        report = build_report(result, show_secrets=False, fail_on=DEFAULT_FAIL_ON)  # redacted, like every output
        summary = {
            "findings": len(report["findings"]),
            "severity": dict(report["summary"]),
            "gate": {
                "fail_on": report["gate"]["fail_on"],
                "failed": report["gate"]["failed"],
                "incomplete": report["gate"]["incomplete"],
            },
            "pages_scanned": len(report["pages"]),
        }
        return json.dumps(report, indent=2, ensure_ascii=False).encode("utf-8"), summary

    # --- for tests and for a graceful stop ---------------------------------------------------------

    def wait_idle(self, timeout: float = 30.0) -> bool:
        """Wait until nothing runs and nothing is queued; False when ``timeout`` seconds were not enough."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            with self._lock:
                busy = bool(self._running)
            if not busy and self._repo.count_scans("queued") == 0 and self._repo.count_scans("running") == 0:
                return True
            time.sleep(0.02)
        return False
