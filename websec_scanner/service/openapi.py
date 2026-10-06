"""The public contract, ``docs/openapi.yaml``, made from the code.

    python -m websec_scanner.service.openapi --write docs/openapi.yaml

A test compares the committed file with what the code says today, so the contract cannot drift from the service.
"""

from __future__ import annotations

import argparse
import sys
import tempfile
from pathlib import Path

import yaml

from .api import create_app
from .config import Settings


def build_spec() -> dict:
    with tempfile.TemporaryDirectory() as folder:  # create_app opens a database; this one is thrown away
        return create_app(Settings(data_dir=Path(folder))).openapi()


def dump(spec: dict) -> str:
    return yaml.safe_dump(spec, sort_keys=False, allow_unicode=True, width=110)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Print or write the OpenAPI document of the service")
    parser.add_argument("--write", metavar="FILE", help="Write the document to FILE instead of printing it")
    args = parser.parse_args(argv)
    text = dump(build_spec())
    if args.write:
        Path(args.write).write_text(text, encoding="utf-8")
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
