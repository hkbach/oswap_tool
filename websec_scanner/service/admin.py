"""The operator's tool: make agencies and API keys (decision D12). There is no public API for this on purpose.

    python -m websec_scanner.service.admin --data-dir DIR create-agency "Agency name"
    python -m websec_scanner.service.admin --data-dir DIR create-key ag_... --name backend [--scope clients:read ...]
    python -m websec_scanner.service.admin --data-dir DIR list-agencies
    python -m websec_scanner.service.admin --data-dir DIR list-keys ag_...
    python -m websec_scanner.service.admin --data-dir DIR revoke-key key_...
    python -m websec_scanner.service.admin --data-dir DIR suspend-agency ag_...   (and activate-agency)

A new key is printed once, on its own line, and is not recoverable: only a hash is kept. It needs the standard
library only (no FastAPI).
"""

from __future__ import annotations

import argparse
import json
import sys

from . import ids, security
from .config import Settings
from .db import NotFound, Repository


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="websec-service-admin", description=__doc__.split("\n\n")[0])
    parser.add_argument(
        "--data-dir",
        help="Where the service keeps its data (default: WEBSEC_SERVICE_DATA_DIR, else ./websec-service-data)",
    )
    parser.add_argument("--json", action="store_true", help="Print the result as JSON")
    commands = parser.add_subparsers(dest="command", required=True)

    create_agency = commands.add_parser("create-agency", help="Make an agency")
    create_agency.add_argument("name")

    create_key = commands.add_parser("create-key", help="Make an API key for an agency (printed once)")
    create_key.add_argument("agency_id")
    create_key.add_argument("--name", required=True, help="A label for you, e.g. the system that will use the key")
    create_key.add_argument(
        "--scope",
        action="append",
        choices=security.SCOPES,
        help=f"Repeatable. Default: every scope ({', '.join(security.SCOPES)})",
    )
    create_key.add_argument("--expires-days", type=int, help="The key stops working after this many days")

    commands.add_parser("list-agencies", help="List the agencies")
    list_keys = commands.add_parser("list-keys", help="List an agency's keys (never their secrets)")
    list_keys.add_argument("agency_id")
    revoke = commands.add_parser("revoke-key", help="Stop a key from working, for good")
    revoke.add_argument("key_id")
    suspend = commands.add_parser("suspend-agency", help="Every key of the agency stops working until it is activated")
    suspend.add_argument("agency_id")
    activate = commands.add_parser("activate-agency", help="Let a suspended agency's keys work again")
    activate.add_argument("agency_id")
    return parser


def _check_id(parser: argparse.ArgumentParser, kind: str, value: str) -> str:
    if not ids.is_valid(kind, value):
        parser.error(f"{value!r} is not a valid {kind} id")
    return value


def main(argv: list[str] | None = None, out=None) -> int:
    out = out or sys.stdout
    parser = build_parser()
    args = parser.parse_args(argv)
    settings = Settings.from_args(args.data_dir)
    repo = Repository(settings.db_path)
    repo.migrate()

    def show(value, text: str) -> None:
        print(json.dumps(value, indent=2) if args.json else text, file=out)

    try:
        if args.command == "create-agency":
            agency = repo.create_agency(args.name.strip() or parser.error("the name is empty"))
            show(agency, f"{agency['agency_id']}  {agency['name']}")
        elif args.command == "create-key":
            _check_id(parser, "agency", args.agency_id)
            if args.expires_days is not None and args.expires_days < 1:
                parser.error("--expires-days must be 1 or more")
            record, full = repo.create_key(
                args.agency_id, args.name, list(args.scope or security.SCOPES), expires_in_days=args.expires_days
            )
            print("Copy this key now: it is shown once and cannot be recovered.", file=sys.stderr)
            show({**record, "api_key": full}, full)
        elif args.command == "list-agencies":
            agencies = repo.list_agencies()
            show(agencies, "\n".join(f"{a['agency_id']}  {a['status']:<9}  {a['name']}" for a in agencies) or "(none)")
        elif args.command == "list-keys":
            keys = repo.list_keys(_check_id(parser, "agency", args.agency_id))
            lines = [
                f"{k['key_id']}  wsk_{k['handle']}_...  {'revoked' if k['revoked_at'] else 'active':<8}  "
                f"{','.join(k['scopes']) or '-'}  {k['name']}"
                for k in keys
            ]
            show(keys, "\n".join(lines) or "(none)")
        elif args.command == "revoke-key":
            repo.revoke_key(_check_id(parser, "key", args.key_id))
            show({"key_id": args.key_id, "revoked": True}, f"revoked {args.key_id}")
        else:  # suspend-agency, activate-agency
            status = "suspended" if args.command == "suspend-agency" else "active"
            repo.set_agency_status(_check_id(parser, "agency", args.agency_id), status)
            show({"agency_id": args.agency_id, "status": status}, f"{args.agency_id} is now {status}")
    except NotFound as exc:
        print(f"error: not found: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
