"""Per-scan traffic limits: how fast, how many, how long (FR-AUTHZ-05).

One ``ScanLimiter`` is created per scan and consulted before every outbound request,
including the TLS handshakes that bypass the HTTP session. It is thread-safe because
the sensitive-path check fetches on a worker pool.

Limits are opt-in: a scanner with no limits configured behaves exactly as before.
"""

from __future__ import annotations

import threading
import time
from urllib.parse import urlsplit

# How long to hold back after a target answers 429/503 without a usable Retry-After,
# doubling for each further push-back so a struggling target gets more room each time.
_BACKOFF_SECONDS = 2.0
_MAX_BACKOFF_SECONDS = 60.0


class ScanLimitReached(Exception):
    """A scan hit ``--max-requests`` or ``--max-duration`` and must stop.

    Deliberately not a ``requests.exceptions.RequestException``: ``safe_get()`` and
    ``get_limited()`` swallow those and return an error string, which would let the scan
    carry on sending requests after the cap.
    """


class ScanLimiter:
    """Decides when the next request may go out, and when the scan must stop."""

    def __init__(
        self,
        rate_limit: float | None = None,
        max_requests: int | None = None,
        max_duration: float | None = None,
        clock=time.monotonic,
        sleep=time.sleep,
    ) -> None:
        if rate_limit is not None and rate_limit <= 0:
            raise ValueError("rate_limit must be greater than 0 requests per second")
        if max_requests is not None and max_requests <= 0:
            raise ValueError("max_requests must be greater than 0")
        if max_duration is not None and max_duration <= 0:
            raise ValueError("max_duration must be greater than 0 seconds")

        self._rate_limit = rate_limit
        self._interval = 1.0 / rate_limit if rate_limit else 0.0
        self._max_requests = max_requests
        self._max_duration = float(max_duration) if max_duration is not None else None
        self._clock = clock
        self._sleep = sleep

        self._lock = threading.Lock()
        self._requests = 0
        self._slowdowns = 0
        self._stopped_by: str | None = None
        self._deadline = clock() + max_duration if max_duration is not None else None
        # Earliest time the next request may start, globally and per host.
        self._next_global = 0.0
        self._next_by_host: dict[str, float] = {}

    def acquire(self, url: str) -> None:
        """Count one outbound request, waiting if the rate requires it.

        Raises ``ScanLimitReached`` when a cap is hit; the request must not be sent.
        """
        host = urlsplit(url).hostname or ""
        with self._lock:
            now = self._clock()
            self._check_caps(now)
            start = max(now, self._next_global, self._next_by_host.get(host, 0.0))
            # Waiting past the deadline is pointless: stop now rather than sleep into it.
            if self._deadline is not None and start >= self._deadline:
                self._stop("max-duration")
            if self._interval:
                self._next_global = start + self._interval
                self._next_by_host[host] = start + self._interval
            self._requests += 1

        # Sleep to the absolute slot, not for a precomputed duration: between releasing the
        # lock and sleeping, this thread may already have been descheduled for a while.
        remaining = start - self._clock()
        if remaining > 0:
            self._sleep(remaining)

    def note_response(self, url: str, status: int, retry_after: str | None = None) -> None:
        """Back off when the target says it is overloaded (429/503)."""
        if status not in (429, 503):
            return
        host = urlsplit(url).hostname or ""
        with self._lock:
            self._slowdowns += 1
            penalty = _parse_retry_after(retry_after)
            if penalty is None:
                penalty = min(_BACKOFF_SECONDS * (2 ** (self._slowdowns - 1)), _MAX_BACKOFF_SECONDS)
            resume = self._clock() + penalty
            self._next_global = max(self._next_global, resume)
            self._next_by_host[host] = max(self._next_by_host.get(host, 0.0), resume)

    def snapshot(self) -> dict:
        """What the report says about this scan's limits (SRS 6.2, ``limits``)."""
        with self._lock:
            return {
                "rate_limit": self._rate_limit,
                "max_requests": self._max_requests,
                "max_duration": self._max_duration,
                "requests_sent": self._requests,
                "slowdowns": self._slowdowns,
                "stopped_by": self._stopped_by,
            }

    @property
    def stopped(self) -> bool:
        with self._lock:
            return self._stopped_by is not None

    def _check_caps(self, now: float) -> None:
        """Caller holds the lock."""
        if self._max_requests is not None and self._requests >= self._max_requests:
            self._stop("max-requests")
        if self._deadline is not None and now >= self._deadline:
            self._stop("max-duration")

    def _stop(self, reason: str) -> None:
        """Caller holds the lock."""
        self._stopped_by = reason
        if reason == "max-requests":
            raise ScanLimitReached(f"stopped after {self._requests} requests (--max-requests {self._max_requests})")
        raise ScanLimitReached(f"stopped after {self._max_duration:g}s (--max-duration {self._max_duration:g})")


def _parse_retry_after(value: str | None) -> float | None:
    """Seconds from a Retry-After header, or None if it is absent or not a plain number.

    Only the delta-seconds form is honoured; an HTTP-date would need a trusted clock
    comparison against the target's, which a scanner should not rely on.
    """
    if value is None:
        return None
    try:
        seconds = float(value.strip())
    except (ValueError, AttributeError):
        return None
    return min(seconds, _MAX_BACKOFF_SECONDS) if seconds > 0 else None
