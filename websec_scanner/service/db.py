"""The service's database: SQLite behind a small repository (decision D12).

SQLite needs no extra service and fits a first deployment; everything the rest of the service knows about storage
is the ``Repository`` class below, so a PostgreSQL implementation can replace it without touching the API. Each
call opens its own short connection (WAL mode, foreign keys on), so request threads never share one.

Times are UTC ISO-8601 strings ending in ``Z``. Scan results are not in the database: they are JSON files
(``config.Settings.results_dir``); the database holds who owns what and a summary.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path

from . import ids, security

SCHEMA_VERSION = 2
_MIGRATIONS: dict[int, str] = {
    1: """
    CREATE TABLE agencies (
        agency_id  TEXT PRIMARY KEY,
        name       TEXT NOT NULL,
        status     TEXT NOT NULL CHECK (status IN ('active', 'suspended')),
        created_at TEXT NOT NULL
    );
    CREATE TABLE api_keys (
        key_id       TEXT PRIMARY KEY,
        agency_id    TEXT NOT NULL REFERENCES agencies (agency_id),
        name         TEXT NOT NULL,
        handle       TEXT NOT NULL UNIQUE,
        secret_hash  TEXT NOT NULL,
        scopes       TEXT NOT NULL,
        created_at   TEXT NOT NULL,
        expires_at   TEXT,
        revoked_at   TEXT,
        last_used_at TEXT
    );
    CREATE INDEX api_keys_by_agency ON api_keys (agency_id);
    CREATE TABLE clients (
        client_id    TEXT PRIMARY KEY,
        agency_id    TEXT NOT NULL REFERENCES agencies (agency_id),
        display_name TEXT NOT NULL,
        external_ref TEXT,
        metadata     TEXT NOT NULL,
        status       TEXT NOT NULL CHECK (status IN ('active', 'deleted')),
        created_at   TEXT NOT NULL,
        updated_at   TEXT NOT NULL
    );
    CREATE INDEX clients_by_agency ON clients (agency_id, client_id);
    CREATE UNIQUE INDEX clients_external_ref ON clients (agency_id, external_ref)
        WHERE external_ref IS NOT NULL AND status = 'active';
    CREATE TABLE audit_log (
        id        INTEGER PRIMARY KEY AUTOINCREMENT,
        at        TEXT NOT NULL,
        agency_id TEXT,
        key_id    TEXT,
        action    TEXT NOT NULL,
        subject   TEXT,
        ip        TEXT,
        detail    TEXT NOT NULL
    );
    CREATE INDEX audit_by_agency ON audit_log (agency_id, id);
    """,
    2: """
    CREATE TABLE scans (
        scan_id         TEXT PRIMARY KEY,
        agency_id       TEXT NOT NULL REFERENCES agencies (agency_id),
        client_id       TEXT NOT NULL REFERENCES clients (client_id),
        target          TEXT NOT NULL,
        target_host     TEXT NOT NULL,
        checks          TEXT NOT NULL,
        crawl           INTEGER NOT NULL,
        status          TEXT NOT NULL CHECK (status IN ('queued', 'running', 'completed', 'failed')),
        created_at      TEXT NOT NULL,
        started_at      TEXT,
        finished_at     TEXT,
        summary         TEXT,
        error_code      TEXT,
        result_path     TEXT,
        attestation     TEXT NOT NULL
    );
    CREATE INDEX scans_by_agency ON scans (agency_id, scan_id);
    CREATE INDEX scans_by_client ON scans (agency_id, client_id, scan_id);
    CREATE INDEX scans_by_status ON scans (status, scan_id);
    CREATE TABLE idempotency (
        agency_id  TEXT NOT NULL REFERENCES agencies (agency_id),
        key        TEXT NOT NULL,
        body_hash  TEXT NOT NULL,
        scan_id    TEXT NOT NULL REFERENCES scans (scan_id),
        created_at TEXT NOT NULL,
        PRIMARY KEY (agency_id, key)
    );
    """,
}


class DuplicateExternalRef(Exception):
    """An active client of this agency already has this ``external_ref``."""


class QueueFull(Exception):
    """Too many scans are waiting (in total, or for this agency)."""


class IdempotencyConflict(Exception):
    """An Idempotency-Key was used before for a request with a different body."""


class NotFound(Exception):
    """No such record for this agency (also what another agency's id gives: its existence is not revealed)."""


def utc_now() -> datetime:
    return datetime.now(UTC)


def to_iso(moment: datetime) -> str:
    return moment.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


class Repository:
    def __init__(self, path: Path, clock: Callable[[], datetime] = utc_now) -> None:
        self.path = Path(path)
        self._clock = clock
        self._touched: dict[str, datetime] = {}  # key_id -> when its last_used_at was written

    # --- connection and migrations ---------------------------------------------------------------

    @contextmanager
    def _connect(self, write: bool = True) -> Iterator[sqlite3.Connection]:
        """A connection in one transaction. A reader does not take the write lock: WAL lets it run beside a writer."""
        connection = sqlite3.connect(self.path, timeout=5, isolation_level=None)  # we control transactions
        connection.row_factory = sqlite3.Row
        try:
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute("PRAGMA busy_timeout = 5000")
            connection.execute("PRAGMA journal_mode = WAL")
            connection.execute("BEGIN IMMEDIATE" if write else "BEGIN")
            try:
                yield connection
            except BaseException:
                connection.execute("ROLLBACK")
                raise
            else:
                connection.execute("COMMIT")
        finally:
            connection.close()

    def migrate(self) -> int:
        """Bring the database to ``SCHEMA_VERSION``; running it again changes nothing. Returns the version."""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as db:
            db.execute(
                "CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)"
            )
            done = {row["version"] for row in db.execute("SELECT version FROM schema_migrations")}
            if done and max(done) > SCHEMA_VERSION:
                raise RuntimeError(
                    f"The database is at schema version {max(done)}, newer than this service understands "
                    f"({SCHEMA_VERSION})."
                )
            for version, script in sorted(_MIGRATIONS.items()):
                if version in done:
                    continue
                for statement in (part.strip() for part in script.split(";")):
                    if statement:
                        db.execute(statement)
                db.execute("INSERT INTO schema_migrations VALUES (?, ?)", (version, to_iso(self._clock())))
            return SCHEMA_VERSION

    def ping(self) -> bool:
        try:
            with self._connect(write=False) as db:
                db.execute("SELECT 1")
            return True
        except sqlite3.Error:
            return False

    def _now(self) -> str:
        return to_iso(self._clock())

    def now_iso(self) -> str:
        return self._now()

    # --- agencies and keys (made by the operator, see admin.py) ----------------------------------

    def create_agency(self, name: str) -> dict:
        agency = {"agency_id": ids.new_id("agency"), "name": name, "status": "active", "created_at": self._now()}
        with self._connect() as db:
            db.execute("INSERT INTO agencies VALUES (:agency_id, :name, :status, :created_at)", agency)
            self._audit(db, "agency.create", agency_id=agency["agency_id"], subject=agency["agency_id"])
        return agency

    def get_agency(self, agency_id: str) -> dict | None:
        with self._connect(write=False) as db:
            row = db.execute("SELECT * FROM agencies WHERE agency_id = ?", (agency_id,)).fetchone()
        return dict(row) if row else None

    def list_agencies(self) -> list[dict]:
        with self._connect(write=False) as db:
            return [dict(row) for row in db.execute("SELECT * FROM agencies ORDER BY agency_id")]

    def set_agency_status(self, agency_id: str, status: str) -> None:
        with self._connect() as db:
            changed = db.execute("UPDATE agencies SET status = ? WHERE agency_id = ?", (status, agency_id)).rowcount
            if not changed:
                raise NotFound(agency_id)
            self._audit(db, f"agency.{status}", agency_id=agency_id, subject=agency_id)

    def create_key(
        self, agency_id: str, name: str, scopes: list[str], expires_in_days: int | None = None
    ) -> tuple[dict, str]:
        """``(record, full key)``. The full key is returned here and nowhere else: only its hash is kept."""
        if self.get_agency(agency_id) is None:
            raise NotFound(agency_id)
        new = security.generate_key()
        expires = to_iso(self._clock() + timedelta(days=expires_in_days)) if expires_in_days else None
        record = {
            "key_id": ids.new_id("key"),
            "agency_id": agency_id,
            "name": name,
            "handle": new.handle,
            "scopes": security.parse_scopes(scopes),
            "created_at": self._now(),
            "expires_at": expires,
        }
        with self._connect() as db:
            db.execute(
                "INSERT INTO api_keys (key_id, agency_id, name, handle, secret_hash, scopes, created_at, expires_at)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    record["key_id"],
                    agency_id,
                    name,
                    new.handle,
                    new.secret_hash,
                    json.dumps(record["scopes"]),
                    record["created_at"],
                    expires,
                ),
            )
            self._audit(db, "key.create", agency_id=agency_id, key_id=record["key_id"], subject=record["key_id"])
        return record, new.full

    def list_keys(self, agency_id: str) -> list[dict]:
        with self._connect(write=False) as db:
            rows = db.execute(
                "SELECT key_id, agency_id, name, handle, scopes, created_at, expires_at, revoked_at, last_used_at"
                " FROM api_keys WHERE agency_id = ? ORDER BY key_id",
                (agency_id,),
            ).fetchall()
        return [{**dict(row), "scopes": json.loads(row["scopes"])} for row in rows]

    def revoke_key(self, key_id: str) -> None:
        with self._connect() as db:
            row = db.execute("SELECT agency_id FROM api_keys WHERE key_id = ?", (key_id,)).fetchone()
            if row is None:
                raise NotFound(key_id)
            db.execute(
                "UPDATE api_keys SET revoked_at = COALESCE(revoked_at, ?) WHERE key_id = ?", (self._now(), key_id)
            )
            self._audit(db, "key.revoke", agency_id=row["agency_id"], key_id=key_id, subject=key_id)

    def find_key(self, handle: str) -> dict | None:
        """The key with this handle, with its agency's status, or None. Includes the stored secret hash."""
        with self._connect(write=False) as db:
            row = db.execute(
                "SELECT k.*, a.status AS agency_status FROM api_keys k"
                " JOIN agencies a USING (agency_id) WHERE k.handle = ?",
                (handle,),
            ).fetchone()
        return {**dict(row), "scopes": json.loads(row["scopes"])} if row else None

    def touch_key(self, key_id: str, resolution_seconds: int = 60) -> None:
        """Note that the key was used, at most once per ``resolution_seconds`` (every request would be a write)."""
        now = self._clock()
        last = self._touched.get(key_id)
        if last is not None and now - last < timedelta(seconds=resolution_seconds):
            return  # written recently by this process: no database call at all
        self._touched[key_id] = now
        floor = to_iso(now - timedelta(seconds=resolution_seconds))
        with self._connect() as db:
            db.execute(
                "UPDATE api_keys SET last_used_at = ? WHERE key_id = ? AND (last_used_at IS NULL OR last_used_at < ?)",
                (to_iso(now), key_id, floor),
            )

    # --- clients ---------------------------------------------------------------------------------

    def create_client(
        self,
        agency_id: str,
        display_name: str,
        external_ref: str | None,
        metadata: dict,
        *,
        key_id: str | None = None,
        ip: str | None = None,
    ) -> dict:
        now = self._now()
        client = {
            "client_id": ids.new_id("client"),
            "display_name": display_name,
            "external_ref": external_ref,
            "metadata": metadata,
            "created_at": now,
            "updated_at": now,
        }
        with self._connect() as db:
            try:
                db.execute(
                    "INSERT INTO clients (client_id, agency_id, display_name, external_ref, metadata, status,"
                    " created_at, updated_at)"
                    " VALUES (?, ?, ?, ?, ?, 'active', ?, ?)",
                    (client["client_id"], agency_id, display_name, external_ref, json.dumps(metadata), now, now),
                )
            except sqlite3.IntegrityError as exc:
                if "UNIQUE" not in str(exc):
                    raise
                raise DuplicateExternalRef(external_ref) from exc
            self._audit(db, "client.create", agency_id=agency_id, key_id=key_id, subject=client["client_id"], ip=ip)
        return client

    @staticmethod
    def _client(row: sqlite3.Row) -> dict:
        return {
            "client_id": row["client_id"],
            "display_name": row["display_name"],
            "external_ref": row["external_ref"],
            "metadata": json.loads(row["metadata"]),
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }

    def get_client(self, agency_id: str, client_id: str) -> dict:
        with self._connect(write=False) as db:
            row = db.execute(
                "SELECT * FROM clients WHERE agency_id = ? AND client_id = ? AND status = 'active'",
                (agency_id, client_id),
            ).fetchone()
        if row is None:
            raise NotFound(client_id)
        return self._client(row)

    def list_clients(
        self, agency_id: str, *, external_ref: str | None = None, limit: int = 50, after: str | None = None
    ) -> list[dict]:
        """Up to ``limit`` + 1 active clients of the agency in id order (the extra one says there is more)."""
        query = "SELECT * FROM clients WHERE agency_id = ? AND status = 'active'"
        params: list = [agency_id]
        if external_ref is not None:
            query += " AND external_ref = ?"
            params.append(external_ref)
        if after is not None:
            query += " AND client_id > ?"
            params.append(after)
        query += " ORDER BY client_id LIMIT ?"
        params.append(limit + 1)
        with self._connect(write=False) as db:
            return [self._client(row) for row in db.execute(query, params)]

    def update_client(
        self,
        agency_id: str,
        client_id: str,
        *,
        display_name: str | None,
        metadata: dict | None,
        key_id: str | None = None,
        ip: str | None = None,
    ) -> dict:
        with self._connect() as db:
            row = db.execute(
                "SELECT * FROM clients WHERE agency_id = ? AND client_id = ? AND status = 'active'",
                (agency_id, client_id),
            ).fetchone()
            if row is None:
                raise NotFound(client_id)
            db.execute(
                "UPDATE clients SET display_name = ?, metadata = ?, updated_at = ? WHERE client_id = ?",
                (
                    row["display_name"] if display_name is None else display_name,
                    row["metadata"] if metadata is None else json.dumps(metadata),
                    self._now(),
                    client_id,
                ),
            )
            self._audit(db, "client.update", agency_id=agency_id, key_id=key_id, subject=client_id, ip=ip)
            updated = db.execute("SELECT * FROM clients WHERE client_id = ?", (client_id,)).fetchone()
        return self._client(updated)

    def delete_client(
        self, agency_id: str, client_id: str, *, key_id: str | None = None, ip: str | None = None
    ) -> None:
        """Mark the client deleted: it disappears from every read and its ``external_ref`` can be used again."""
        with self._connect() as db:
            changed = db.execute(
                "UPDATE clients SET status = 'deleted', updated_at = ?"
                " WHERE agency_id = ? AND client_id = ? AND status = 'active'",
                (self._now(), agency_id, client_id),
            ).rowcount
            if not changed:
                raise NotFound(client_id)
            self._audit(db, "client.delete", agency_id=agency_id, key_id=key_id, subject=client_id, ip=ip)

    # --- scans -----------------------------------------------------------------------------------

    @staticmethod
    def _scan(row: sqlite3.Row) -> dict:
        return {
            "scan_id": row["scan_id"],
            "agency_id": row["agency_id"],
            "client_id": row["client_id"],
            "target": row["target"],
            "target_host": row["target_host"],
            "checks": json.loads(row["checks"]),
            "crawl": bool(row["crawl"]),
            "status": row["status"],
            "created_at": row["created_at"],
            "started_at": row["started_at"],
            "finished_at": row["finished_at"],
            "summary": json.loads(row["summary"]) if row["summary"] else None,
            "error_code": row["error_code"],
            "result_path": row["result_path"],
            "attestation": json.loads(row["attestation"]),
        }

    def create_scan(
        self,
        agency_id: str,
        client_id: str,
        *,
        target: str,
        target_host: str,
        checks: list[str],
        crawl: bool,
        statement_version: str,
        idempotency_key: str | None,
        body_hash: str,
        max_queued: int,
        max_queued_per_agency: int,
        idempotency_ttl_seconds: int,
        key_id: str | None = None,
        ip: str | None = None,
    ) -> tuple[dict, bool]:
        """Queue a scan; ``(scan, replayed)``. One transaction, so two requests with the same key cannot both queue one.

        Raises ``NotFound`` (the client is not this agency's), ``IdempotencyConflict`` (the key was used with another
        body) or ``QueueFull``. A repeated key with the same body returns the first scan and queues nothing.
        """
        now = self._clock()
        with self._connect() as db:
            if not db.execute(
                "SELECT 1 FROM clients WHERE agency_id = ? AND client_id = ? AND status = 'active'",
                (agency_id, client_id),
            ).fetchone():
                raise NotFound(client_id)
            if idempotency_key is not None:
                cutoff = to_iso(now - timedelta(seconds=idempotency_ttl_seconds))
                db.execute("DELETE FROM idempotency WHERE created_at <= ?", (cutoff,))
                seen = db.execute(
                    "SELECT body_hash, scan_id FROM idempotency WHERE agency_id = ? AND key = ?",
                    (agency_id, idempotency_key),
                ).fetchone()
                if seen is not None:
                    if seen["body_hash"] != body_hash:
                        raise IdempotencyConflict(idempotency_key)
                    row = db.execute("SELECT * FROM scans WHERE scan_id = ?", (seen["scan_id"],)).fetchone()
                    return self._scan(row), True
            queued = db.execute("SELECT COUNT(*) FROM scans WHERE status = 'queued'").fetchone()[0]
            mine = db.execute(
                "SELECT COUNT(*) FROM scans WHERE status = 'queued' AND agency_id = ?", (agency_id,)
            ).fetchone()[0]
            if queued >= max_queued or mine >= max_queued_per_agency:
                raise QueueFull(agency_id)
            scan_id = ids.new_id("scan")
            created = to_iso(now)
            attestation = {
                "confirmed": True,
                "statement_version": statement_version,
                "key_id": key_id,
                "ip": ip,
                "at": created,
                "target_host": target_host,
            }
            db.execute(
                "INSERT INTO scans (scan_id, agency_id, client_id, target, target_host, checks, crawl, status,"
                " created_at,"
                " attestation) VALUES (?, ?, ?, ?, ?, ?, ?, 'queued', ?, ?)",
                (
                    scan_id,
                    agency_id,
                    client_id,
                    target,
                    target_host,
                    json.dumps(checks),
                    1 if crawl else 0,
                    created,
                    json.dumps(attestation),
                ),
            )
            if idempotency_key is not None:
                db.execute(
                    "INSERT INTO idempotency (agency_id, key, body_hash, scan_id, created_at) VALUES (?, ?, ?, ?, ?)",
                    (agency_id, idempotency_key, body_hash, scan_id, created),
                )
            self._audit(
                db,
                "scan.create",
                agency_id=agency_id,
                key_id=key_id,
                subject=scan_id,
                ip=ip,
                detail={"client_id": client_id, "statement_version": statement_version, "crawl": crawl},
            )
            return self._scan(db.execute("SELECT * FROM scans WHERE scan_id = ?", (scan_id,)).fetchone()), False

    def get_scan(self, agency_id: str, scan_id: str) -> dict:
        with self._connect(write=False) as db:
            row = db.execute("SELECT * FROM scans WHERE agency_id = ? AND scan_id = ?", (agency_id, scan_id)).fetchone()
        if row is None:
            raise NotFound(scan_id)
        return self._scan(row)

    def list_scans(
        self,
        agency_id: str,
        *,
        client_id: str | None = None,
        status: str | None = None,
        limit: int = 50,
        before: str | None = None,
    ) -> list[dict]:
        """Up to ``limit`` + 1 scans of the agency, newest first (the extra one says there is more)."""
        query = "SELECT * FROM scans WHERE agency_id = ?"
        params: list = [agency_id]
        if client_id is not None:
            query += " AND client_id = ?"
            params.append(client_id)
        if status is not None:
            query += " AND status = ?"
            params.append(status)
        if before is not None:
            query += " AND scan_id < ?"
            params.append(before)
        query += " ORDER BY scan_id DESC LIMIT ?"
        params.append(limit + 1)
        with self._connect(write=False) as db:
            return [self._scan(row) for row in db.execute(query, params)]

    def queued_scans(self, limit: int = 1000) -> list[dict]:
        """Scans waiting to run, oldest first, from every agency (the runner decides which may start)."""
        with self._connect(write=False) as db:
            rows = db.execute(
                "SELECT * FROM scans WHERE status = 'queued' ORDER BY scan_id LIMIT ?", (limit,)
            ).fetchall()
        return [self._scan(row) for row in rows]

    def count_scans(self, status: str) -> int:
        with self._connect(write=False) as db:
            return db.execute("SELECT COUNT(*) FROM scans WHERE status = ?", (status,)).fetchone()[0]

    def mark_running(self, scan_id: str) -> bool:
        """queued -> running; False when the scan is not queued any more."""
        with self._connect() as db:
            return bool(
                db.execute(
                    "UPDATE scans SET status = 'running', started_at = ? WHERE scan_id = ? AND status = 'queued'",
                    (self._now(), scan_id),
                ).rowcount
            )

    def finish_scan(self, scan_id: str, summary: dict, result_path: str) -> None:
        with self._connect() as db:
            db.execute(
                "UPDATE scans SET status = 'completed', finished_at = ?, summary = ?, result_path = ?"
                " WHERE scan_id = ? AND status = 'running'",
                (self._now(), json.dumps(summary), result_path, scan_id),
            )

    def fail_scan(self, scan_id: str, error_code: str) -> None:
        with self._connect() as db:
            db.execute(
                "UPDATE scans SET status = 'failed', finished_at = ?, error_code = ?"
                " WHERE scan_id = ? AND status IN ('queued', 'running')",
                (self._now(), error_code, scan_id),
            )

    def recover_interrupted(self) -> int:
        """Scans left ``running`` by a service that stopped are failed (``interrupted``); returns how many."""
        with self._connect() as db:
            return db.execute(
                "UPDATE scans SET status = 'failed', finished_at = ?, error_code = 'interrupted'"
                " WHERE status = 'running'",
                (self._now(),),
            ).rowcount

    # --- audit -----------------------------------------------------------------------------------

    def _audit(
        self,
        db: sqlite3.Connection,
        action: str,
        *,
        agency_id: str | None = None,
        key_id: str | None = None,
        subject: str | None = None,
        ip: str | None = None,
        detail: dict | None = None,
    ) -> None:
        db.execute(
            "INSERT INTO audit_log (at, agency_id, key_id, action, subject, ip, detail) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (self._now(), agency_id, key_id, action, subject, ip, json.dumps(detail or {})),
        )

    def audit_entries(self, agency_id: str | None = None) -> list[dict]:
        with self._connect(write=False) as db:
            if agency_id is None:
                rows = db.execute("SELECT * FROM audit_log ORDER BY id").fetchall()
            else:
                rows = db.execute("SELECT * FROM audit_log WHERE agency_id = ? ORDER BY id", (agency_id,)).fetchall()
        return [{**dict(row), "detail": json.loads(row["detail"])} for row in rows]
