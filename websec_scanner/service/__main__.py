"""Run the service: ``python -m websec_scanner.service [--host 127.0.0.1] [--port 8780] [--data-dir DIR]``.

It listens on plain HTTP and is meant to sit behind a reverse proxy that terminates TLS (decision D12): an API key
must never travel in clear text over a network you do not control.
"""

from __future__ import annotations

import argparse
import sys

from .config import DEFAULT_PORT, Settings

MISSING = (
    "The service needs the optional dependencies: pip install 'websec-scanner[service]'\n"
    "(the CLI and the local web UI do not).\n"
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m websec_scanner.service", description=__doc__.split("\n\n")[0])
    parser.add_argument("--host", default="127.0.0.1", help="Interface to bind (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help=f"Port (default: {DEFAULT_PORT})")
    parser.add_argument(
        "--data-dir", help="Where the database and the results are kept (default: WEBSEC_SERVICE_DATA_DIR)"
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        import uvicorn

        from .api import create_app
    except ImportError:
        sys.stderr.write(MISSING)
        return 2
    try:
        settings = Settings.from_args(args.data_dir)
        app = create_app(settings)
    except (ValueError, RuntimeError) as exc:
        sys.stderr.write(f"error: {exc}\n")
        return 2
    if settings.allow_private_targets:
        sys.stderr.write(
            "WARNING: WEBSEC_SERVICE_ALLOW_PRIVATE_TARGETS is on: scans may connect to loopback and private addresses. "
            "This is for development only; never run a service that agencies can reach like this.\n"
        )
    uvicorn.run(app, host=args.host, port=args.port, log_level="info", server_header=False)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
