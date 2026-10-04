"""FR-AUTHZ-05 / FR-QA-05: the limits a whole scan runs under, measured end to end.

These drive real scans against the local mock server, so they also prove the limiter sees
the request paths that bypass the HTTP session: redirect hops and TLS handshakes.
"""

from __future__ import annotations

import time

import pytest
from conftest import QuietHandler
from mock_server import Handler as MockHandler

from websec_scanner import cli
from websec_scanner.limits import ScanLimiter, ScanLimitReached
from websec_scanner.output import build_report


class CountingHandler(QuietHandler):
    """Records the arrival time of every request, so a test can measure the real rate."""

    arrivals: list[float] = []

    def do_GET(self):
        type(self).arrivals.append(time.monotonic())
        self.send(200, b"home")


@pytest.fixture
def counting_server(http_server):
    CountingHandler.arrivals = []
    url = http_server(CountingHandler)
    return url, CountingHandler


def _assert_within_rate(arrivals: list[float], rate: float) -> None:
    """What the target actually experiences: the average rate, and no burst inside any window.

    Per-pair spacing is not asserted: the mock server records arrivals on a thread per
    connection, so two adjacent timestamps can be reordered by a few milliseconds even when
    the requests were sent correctly spaced. The exact spacing is covered by the fake-clock
    tests in test_limits.py.
    """
    assert len(arrivals) > 5, "too few requests to measure a rate"
    elapsed = arrivals[-1] - arrivals[0]
    average = (len(arrivals) - 1) / elapsed if elapsed else float("inf")
    assert average <= rate * 1.25, f"average {average:.1f} req/s exceeds the {rate} req/s limit"
    # No sustained burst either: no one-second window may hold much more than the rate allows.
    for i, start in enumerate(arrivals):
        in_window = sum(1 for a in arrivals[i:] if a - start < 1.0)
        assert in_window <= rate * 1.25 + 1, f"{in_window} requests within one second at index {i}"


def test_the_scanner_keeps_to_the_rate_it_was_given(counting_server):
    # FR-QA-05: measured against the server's own arrival times, not the limiter's bookkeeping.
    url, handler = counting_server
    rate = 25.0  # fast enough to keep the test short, slow enough to be measurable
    cli.run_scan(url, rate_limit=rate, groups=["directory-listing"])
    _assert_within_rate(handler.arrivals, rate)


def test_the_rate_holds_even_when_checks_run_on_the_worker_pool(counting_server):
    url, handler = counting_server
    rate = 25.0
    cli.run_scan(url, rate_limit=rate, workers=5, groups=["exposed-files"])
    _assert_within_rate(handler.arrivals, rate)


def test_an_unlimited_scan_is_not_slowed_down(counting_server):
    url, handler = counting_server
    cli.run_scan(url, groups=["exposed-files"])
    arrivals = handler.arrivals
    assert len(arrivals) > 5
    assert arrivals[-1] - arrivals[0] < 2.0  # no artificial spacing


def _stop_lines(result) -> int:
    """FR-LIM-03 fixes the prefix, and a scan may only say it once."""
    return len([e for e in result.errors if e.startswith("Scan stopped early")])


def test_max_requests_stops_the_scan_and_says_so(http_server):
    result = cli.run_scan(http_server(MockHandler), max_requests=3)
    assert result.limits["stopped_by"] == "max-requests"
    assert result.limits["requests_sent"] == 3
    assert _stop_lines(result) == 1, result.errors  # one line, not one per worker
    assert any("--max-requests" in e for e in result.errors), result.errors


def test_max_duration_stops_the_scan(http_server):
    result = cli.run_scan(http_server(MockHandler), max_duration=0.001)
    assert result.limits["stopped_by"] == "max-duration"
    assert _stop_lines(result) == 1, result.errors
    assert any("--max-duration" in e for e in result.errors), result.errors


def test_a_stopped_scan_is_reported_as_incomplete(http_server):
    report = build_report(cli.run_scan(http_server(MockHandler), max_requests=2))
    assert report["gate"]["incomplete"] is True
    assert report["limits"]["stopped_by"] == "max-requests"


def test_an_ordinary_scan_reports_its_limits_as_unset(http_server):
    report = build_report(cli.run_scan(http_server(MockHandler)))
    assert report["gate"]["incomplete"] is False
    assert report["limits"]["rate_limit"] is None
    assert report["limits"]["stopped_by"] is None
    assert report["limits"]["requests_sent"] > 0


def test_every_redirect_hop_is_counted(http_server):
    class Redirecting(QuietHandler):
        def do_GET(self):
            if self.path == "/":
                self.send(302, b"", [("Location", "/one")])
            elif self.path == "/one":
                self.send(302, b"", [("Location", "/two")])
            else:
                self.send(200, b"done")

    # One session.get() but three on-wire requests: the cap has to see all three.
    result = cli.run_scan(http_server(Redirecting), max_requests=2, groups=["headers"])
    assert result.limits["requests_sent"] == 2
    assert result.limits["stopped_by"] == "max-requests"


def test_tls_handshakes_are_counted_even_though_they_bypass_the_session(https_server):
    url, _port = https_server(QuietHandler)
    # Only the tls group runs, and its handshakes never touch the HTTP session; without the
    # explicit limiter the TLS check would be invisible to --max-requests.
    tls_only = cli.run_scan(url, groups=["tls"]).limits["requests_sent"]
    baseline_only = cli.run_scan(url, groups=["cors"]).limits["requests_sent"]
    assert tls_only > baseline_only, "TLS handshakes are not being counted"


def test_the_limiter_is_shared_by_the_worker_pool(http_server):
    # exposed-files fetches on 5 threads; the cap must still be exact.
    result = cli.run_scan(http_server(MockHandler), max_requests=6, workers=5, groups=["exposed-files"])
    assert result.limits["requests_sent"] == 6


def test_a_reached_limit_is_not_reported_as_a_broken_check(http_server):
    result = cli.run_scan(http_server(MockHandler), max_requests=2)
    assert not [e for e in result.errors if "failed:" in e], result.errors


def test_run_scan_rejects_a_nonsense_rate(http_server):
    with pytest.raises(ValueError):
        cli.run_scan(http_server(MockHandler), rate_limit=0)


def test_the_limiter_type_is_what_the_scan_uses():
    limiter = ScanLimiter(max_requests=1)
    limiter.acquire("https://t.example/")
    with pytest.raises(ScanLimitReached):
        limiter.acquire("https://t.example/")
