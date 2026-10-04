"""FR-AUTHZ-05: rate limit, request cap and duration cap for one scan.

The limiter is driven by injectable clock/sleep functions, so these tests assert on the
delays it *asks* for rather than on real elapsed time (FR-QA-05 measures the real thing
against a mock server).
"""

from __future__ import annotations

import threading

import pytest

from websec_scanner.limits import ScanLimiter, ScanLimitReached


class FakeClock:
    """A monotonic clock that only moves when the limiter sleeps (or a test moves it)."""

    def __init__(self) -> None:
        self.now = 1000.0
        self.slept: list[float] = []

    def time(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.slept.append(seconds)
        self.now += seconds


@pytest.fixture
def clock():
    return FakeClock()


def test_no_limits_means_no_waiting(clock):
    limiter = ScanLimiter(clock=clock.time, sleep=clock.sleep)
    for _ in range(50):
        limiter.acquire("https://t.example/a")
    assert clock.slept == []
    assert limiter.snapshot()["requests_sent"] == 50


def test_rate_limit_spaces_requests_out(clock):
    limiter = ScanLimiter(rate_limit=4, clock=clock.time, sleep=clock.sleep)  # 4/s -> 0.25s apart
    for _ in range(4):
        limiter.acquire("https://t.example/a")
    assert clock.slept == [pytest.approx(0.25)] * 3  # the first request is free


def test_rate_limit_does_not_wait_when_the_caller_was_already_slow(clock):
    limiter = ScanLimiter(rate_limit=4, clock=clock.time, sleep=clock.sleep)
    limiter.acquire("https://t.example/a")
    clock.now += 10  # the check itself took longer than the interval
    limiter.acquire("https://t.example/a")
    assert clock.slept == []


def test_the_rate_applies_across_hosts_as_well_as_per_host(clock):
    limiter = ScanLimiter(rate_limit=4, clock=clock.time, sleep=clock.sleep)
    limiter.acquire("https://a.example/x")
    limiter.acquire("https://b.example/x")  # different host, still bound by the global rate
    assert clock.slept == [pytest.approx(0.25)]


def test_max_requests_stops_the_scan(clock):
    limiter = ScanLimiter(max_requests=3, clock=clock.time, sleep=clock.sleep)
    for _ in range(3):
        limiter.acquire("https://t.example/a")
    with pytest.raises(ScanLimitReached) as excinfo:
        limiter.acquire("https://t.example/a")
    assert "--max-requests" in str(excinfo.value)
    assert limiter.snapshot()["stopped_by"] == "max-requests"
    assert limiter.snapshot()["requests_sent"] == 3


def test_max_duration_stops_the_scan(clock):
    limiter = ScanLimiter(max_duration=5, clock=clock.time, sleep=clock.sleep)
    limiter.acquire("https://t.example/a")
    clock.now += 6
    with pytest.raises(ScanLimitReached) as excinfo:
        limiter.acquire("https://t.example/a")
    assert "--max-duration" in str(excinfo.value)
    assert limiter.snapshot()["stopped_by"] == "max-duration"


def test_the_deadline_is_rechecked_after_waiting_for_the_rate(clock):
    # A slow rate must not let the scan sail past --max-duration while it sleeps.
    limiter = ScanLimiter(rate_limit=0.1, max_duration=5, clock=clock.time, sleep=clock.sleep)
    limiter.acquire("https://t.example/a")
    with pytest.raises(ScanLimitReached):
        limiter.acquire("https://t.example/a")  # would have to sleep 10s, past the 5s deadline
    assert limiter.snapshot()["stopped_by"] == "max-duration"


def test_a_limit_is_not_a_request_exception():
    # safe_get()/get_limited() swallow RequestException; a reached limit must not be swallowed.
    import requests

    assert not issubclass(ScanLimitReached, requests.exceptions.RequestException)


@pytest.mark.parametrize("status", [429, 503])
def test_the_scanner_slows_down_when_the_target_pushes_back(clock, status):
    limiter = ScanLimiter(rate_limit=10, clock=clock.time, sleep=clock.sleep)
    limiter.acquire("https://t.example/a")
    limiter.note_response("https://t.example/a", status, retry_after=None)
    limiter.acquire("https://t.example/a")
    assert clock.slept and clock.slept[-1] > 0.1  # longer than the configured 0.1s interval
    assert limiter.snapshot()["slowdowns"] == 1


def test_retry_after_is_honoured(clock):
    limiter = ScanLimiter(clock=clock.time, sleep=clock.sleep)
    limiter.acquire("https://t.example/a")
    limiter.note_response("https://t.example/a", 429, retry_after="2")
    limiter.acquire("https://t.example/a")
    assert clock.slept == [pytest.approx(2.0)]


def test_a_nonsense_retry_after_falls_back_to_the_default_backoff(clock):
    limiter = ScanLimiter(clock=clock.time, sleep=clock.sleep)
    limiter.acquire("https://t.example/a")
    limiter.note_response("https://t.example/a", 429, retry_after="soon please")
    limiter.acquire("https://t.example/a")
    assert clock.slept and clock.slept[-1] > 0


def test_an_ordinary_response_does_not_slow_anything_down(clock):
    limiter = ScanLimiter(clock=clock.time, sleep=clock.sleep)
    limiter.acquire("https://t.example/a")
    limiter.note_response("https://t.example/a", 200, retry_after=None)
    limiter.acquire("https://t.example/a")
    assert clock.slept == []
    assert limiter.snapshot()["slowdowns"] == 0


def test_counting_is_thread_safe():
    # exposure.py fetches sensitive paths on a 5-worker pool, so acquire() runs concurrently.
    limiter = ScanLimiter()
    errors: list[BaseException] = []

    def hammer():
        try:
            for _ in range(200):
                limiter.acquire("https://t.example/a")
        except BaseException as exc:  # noqa: BLE001 - re-raised in the assertion below
            errors.append(exc)

    threads = [threading.Thread(target=hammer) for _ in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors
    assert limiter.snapshot()["requests_sent"] == 1000


def test_max_requests_is_exact_under_concurrency():
    limiter = ScanLimiter(max_requests=50)
    reached = []

    def hammer():
        for _ in range(100):
            try:
                limiter.acquire("https://t.example/a")
            except ScanLimitReached:
                reached.append(1)
                return

    threads = [threading.Thread(target=hammer) for _ in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert limiter.snapshot()["requests_sent"] == 50  # never more than the cap, even with 5 threads
    assert reached


def test_snapshot_reports_the_configured_limits():
    limiter = ScanLimiter(rate_limit=2.5, max_requests=10, max_duration=30)
    assert limiter.snapshot() == {
        "rate_limit": 2.5,
        "max_requests": 10,
        "max_duration": 30.0,
        "requests_sent": 0,
        "slowdowns": 0,
        "stopped_by": None,
    }


def test_an_unlimited_scan_reports_nulls():
    assert ScanLimiter().snapshot() == {
        "rate_limit": None,
        "max_requests": None,
        "max_duration": None,
        "requests_sent": 0,
        "slowdowns": 0,
        "stopped_by": None,
    }


@pytest.mark.parametrize("bad", [0, -1, -0.5])
def test_a_rate_of_zero_or_less_is_rejected(bad):
    with pytest.raises(ValueError):
        ScanLimiter(rate_limit=bad)
