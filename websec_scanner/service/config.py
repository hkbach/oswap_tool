"""Settings of the service, read from the environment (decision D12). No secret is kept here or in the repo."""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path

from ..crawler.crawl import CrawlOptions

API_VERSION = "v1"
DEFAULT_PORT = 8780


@dataclass(frozen=True)
class Settings:
    data_dir: Path
    # What a crawl may do when a request asks for one. The caller sends a boolean; these limits are the operator's.
    crawl: CrawlOptions = field(default_factory=CrawlOptions)
    max_body_bytes: int = 64 * 1024  # every v1 request is a small JSON document
    key_touch_seconds: int = 60  # how often last_used_at of a key is written
    default_page_size: int = 50
    max_page_size: int = 100

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
        """``WEBSEC_SERVICE_DATA_DIR`` (default ``./websec-service-data``) and the optional crawl limits
        ``WEBSEC_SERVICE_CRAWL_DEPTH``, ``..._CRAWL_MAX_PAGES``, ``..._CRAWL_MAX_DURATION``. A bad value is an error
        at start, not a silent default."""
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

        crawl = CrawlOptions(
            max_depth=number("WEBSEC_SERVICE_CRAWL_DEPTH", defaults.max_depth, int),
            max_pages=number("WEBSEC_SERVICE_CRAWL_MAX_PAGES", defaults.max_pages, int),
            max_duration=number("WEBSEC_SERVICE_CRAWL_MAX_DURATION", defaults.max_duration, float),
        )
        return cls(data_dir=Path(env.get("WEBSEC_SERVICE_DATA_DIR") or "websec-service-data"), crawl=crawl)
