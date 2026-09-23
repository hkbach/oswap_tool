import argparse
import sys
from pathlib import Path
from urllib.parse import urlsplit

from owasp_tool import __version__
from owasp_tool.checks import ALL_CHECKS, get_checks
from owasp_tool.config import ScanConfig
from owasp_tool.http import create_client
from owasp_tool.reporting import REPORTERS
from owasp_tool.scanner import run_scan


def _url(value: str) -> str:
    parts = urlsplit(value)
    if parts.scheme not in ("http", "https") or not parts.netloc:
        raise argparse.ArgumentTypeError(f"invalid URL (expected http(s)://host): {value}")
    return value


def _cmd_list_checks(args: argparse.Namespace) -> int:
    for cls in ALL_CHECKS:
        print(f"{cls.id:<24} {cls.owasp:<40} {cls.name}")
    return 0


def _cmd_scan(args: argparse.Namespace) -> int:
    if not args.authorized:
        print(
            "error: pass --authorized to confirm you are allowed to test this target",
            file=sys.stderr,
        )
        return 2
    try:
        checks = get_checks(args.checks.split(",") if args.checks else None)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    config = ScanConfig(timeout=args.timeout, ca_bundle=args.ca_bundle)
    with create_client(config) as client:
        result = run_scan(args.target, checks, client)

    report = REPORTERS[args.format](result)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(report, encoding="utf-8")
    else:
        print(report, end="")
    return 1 if result.errors else 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="owasp-tool",
        description="Security testing tool based on OWASP guidelines. "
        "Only scan targets you are authorized to test.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command")

    list_p = sub.add_parser("list-checks", help="list available checks")
    list_p.set_defaults(handler=_cmd_list_checks)

    scan_p = sub.add_parser("scan", help="scan a target URL")
    scan_p.add_argument("target", type=_url, help="target URL, e.g. https://example.com")
    scan_p.add_argument(
        "--authorized", action="store_true", help="confirm you are authorized to test the target"
    )
    scan_p.add_argument("--checks", help="comma-separated check ids (default: all)")
    scan_p.add_argument("--format", choices=sorted(REPORTERS), default="console")
    scan_p.add_argument("-o", "--output", type=Path, help="write report to file")
    scan_p.add_argument("--timeout", type=float, default=10.0, help="request timeout (seconds)")
    scan_p.add_argument("--ca-bundle", help="path to a custom CA bundle (PEM)")
    scan_p.set_defaults(handler=_cmd_scan)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command is None:
        parser.print_help()
        return 0
    return args.handler(args)
