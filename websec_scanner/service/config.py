"""Settings of the service, read from the environment (decision D12). No secret is kept here or in the repo."""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path

from ..crawler.crawl import CrawlOptions

API_VERSION = "v1"
DEFAULT_PORT = 8780
_TRUE = {"1", "true", "yes", "on"}
_FALSE = {"0", "false", "no", "off"}


@dataclass(frozen=True)
class Settings:
    data_dir: Path
    # What a crawl may do when a request asks for one. The caller sends a boolean; these limits are the operator's.
    crawl: CrawlOptions = field(default_factory=CrawlOptions)
    max_body_bytes: int = 64 * 1024  # every v1 request is a small JSON document
    key_touch_seconds: int = 60  # how often last_used_at of a key is written
    default_page_size: int = 50
    max_page_size: int = 100
    # --- scans (phase 2). A caller cannot change any of these: they are the operator's. ---
    allow_private_targets: bool = False  # development only: lets a scan reach loopback and private addresses
    tls_probe: bool = True  # the TLS probes of the scanner (about 11 extra handshakes), as the CLI does by default
    max_concurrent_scans: int = 4
    max_concurrent_per_agency: int = 2
    max_queued_scans: int = 100
    max_queued_per_agency: int = 20
    scan_rate_limit: float = 10.0  # requests per second of one scan
    scan_max_requests: int = 500
    scan_max_duration: float = 300.0  # seconds
    scan_timeout: int = 10  # seconds per request
    scan_workers: int = 5  # parallel path checks inside one scan
    idempotency_ttl_seconds: int = 24 * 3600
    attestation_versions: tuple[str, ...] = ("v1",)  # the statement versions an agency may confirm

    def __post_init__(self) -> None:
        positive = (
            "max_concurrent_scans",
            "max_concurrent_per_agency",
            "max_queued_scans",
            "max_queued_per_agency",
            "scan_rate_limit",
            "scan_max_requests",
            "scan_max_duration",
            "scan_timeout",
            "scan_workers",
            "idempotency_ttl_seconds",
        )
        for name in positive:
            if getattr(self, name) <= 0:
                raise ValueError(f"{name} must be greater than 0")

    @property
    def db_path(self) -> Path:
        return self.data_dir / "service.db"

    @property
    def results_dir(self) -> Path:
        return self.data_dir / "results"

    @classmethod
    def from_args(cls, data_dir: str | None) -> Settings:
        """The environment, with ``--data-dir`` on top of it when it was given (it does not hide the rest)."""
        env = dict(os.environ)
        if data_dir:
            env["WEBSEC_SERVICE_DATA_DIR"] = data_dir
        return cls.from_env(env)

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> Settings:
        """``WEBSEC_SERVICE_DATA_DIR`` (default ``./websec-service-data``), the crawl limits
        ``WEBSEC_SERVICE_CRAWL_DEPTH``, ``..._CRAWL_MAX_PAGES``, ``..._CRAWL_MAX_DURATION``, and the scan settings
        ``..._MAX_CONCURRENT_SCANS``, ``..._MAX_CONCURRENT_PER_AGENCY``, ``..._MAX_QUEUED_SCANS``,
        ``..._MAX_QUEUED_PER_AGENCY``, ``..._SCAN_RATE_LIMIT``, ``..._SCAN_MAX_REQUESTS``, ``..._SCAN_MAX_DURATION``,
        ``..._TLS_PROBE`` and ``..._ALLOW_PRIVATE_TARGETS`` (true/false). A bad value is an error at start, not a
        silent default."""
        env = os.environ if env is None else env
        defaults = CrawlOptions()

        def number(name: str, default, kind):
            raw = env.get(name)
            if raw is None or raw == "":
                return default
            try:
                return kind(raw)
            except ValueError:
                raise ValueError(f"{name} must be a number, got {raw!r}") from None

        def flag(name: str, default: bool) -> bool:
            raw = (env.get(name) or "").strip().lower()
            if raw == "":
                return default
            if raw in _TRUE:
                return True
            if raw in _FALSE:
                return False
            raise ValueError(f"{name} must be true or false, got {raw!r}")

        crawl = CrawlOptions(
            max_depth=number("WEBSEC_SERVICE_CRAWL_DEPTH", defaults.max_depth, int),
            max_pages=number("WEBSEC_SERVICE_CRAWL_MAX_PAGES", defaults.max_pages, int),
            max_duration=number("WEBSEC_SERVICE_CRAWL_MAX_DURATION", defaults.max_duration, float),
        )
        base = cls(data_dir=Path("."))  # only for its defaults
        prefix = "WEBSEC_SERVICE_"
        return cls(
            data_dir=Path(env.get(prefix + "DATA_DIR") or "websec-service-data"),
            crawl=crawl,
            allow_private_targets=flag(prefix + "ALLOW_PRIVATE_TARGETS", base.allow_private_targets),
            tls_probe=flag(prefix + "TLS_PROBE", base.tls_probe),
            max_concurrent_scans=number(prefix + "MAX_CONCURRENT_SCANS", base.max_concurrent_scans, int),
            max_concurrent_per_agency=number(prefix + "MAX_CONCURRENT_PER_AGENCY", base.max_concurrent_per_agency, int),
            max_queued_scans=number(prefix + "MAX_QUEUED_SCANS", base.max_queued_scans, int),
            max_queued_per_agency=number(prefix + "MAX_QUEUED_PER_AGENCY", base.max_queued_per_agency, int),
            scan_rate_limit=number(prefix + "SCAN_RATE_LIMIT", base.scan_rate_limit, float),
            scan_max_requests=number(prefix + "SCAN_MAX_REQUESTS", base.scan_max_requests, int),
            scan_max_duration=number(prefix + "SCAN_MAX_DURATION", base.scan_max_duration, float),
        )
