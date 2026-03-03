#!/usr/bin/env python3
"""
Supabase migrations runner.

Applies SQL files in supabase/migrations/ (timestamp-prefixed names, e.g. 20260205000000_*.sql)
in order, tracks applied migrations in public.schema_migrations, and is safe to run multiple times.

For production/staging, prefer: supabase link --project-ref <ref> && supabase db push
This script is for environments where the Supabase CLI is not used (e.g. CI with DATABASE_URL).

Requirements:
- SUPABASE_URL + SUPABASE_SERVICE_ROLE_KEY must be set (server-side only)
- DATABASE_URL or SUPABASE_DB_URL preferred for direct Postgres connection
- Alternatively use PGHOST/PGPORT/PGDATABASE/PGUSER/PGPASSWORD
"""

from __future__ import annotations

import hashlib
import os
import re
import sys
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set, Tuple


# Supabase CLI format: 14-digit timestamp + _ + name + .sql (e.g. 20260205000000_scan_results.sql)
MIGRATION_FILENAME_RE = re.compile(r"^\d{14}_.*\.sql$")
CONCURRENT_INDEX_RE = re.compile(r"\bcreate\s+index\s+concurrently\b", re.IGNORECASE)
CONCURRENT_DROP_INDEX_RE = re.compile(r"\bdrop\s+index\s+concurrently\b", re.IGNORECASE)
AUTOCOMMIT_STATEMENTS = [
    re.compile(r"\bvacuum\b", re.IGNORECASE),
    re.compile(r"\breindex\b", re.IGNORECASE),
    re.compile(r"\bcluster\b", re.IGNORECASE),
    re.compile(r"\bcreate\s+database\b", re.IGNORECASE),
    re.compile(r"\bdrop\s+database\b", re.IGNORECASE),
    re.compile(r"\balter\s+system\b", re.IGNORECASE),
]


def discover_migration_files(migrations_dir: Path) -> List[Path]:
    if not migrations_dir.exists():
        raise FileNotFoundError(f"Migrations directory not found: {migrations_dir}")

    files = [
        path
        for path in migrations_dir.iterdir()
        if path.is_file() and MIGRATION_FILENAME_RE.match(path.name)
    ]
    return sorted(files, key=lambda p: p.name)


def compute_checksum(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(8192), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def plan_migrations(
    all_files: List[Path], applied_filenames: Set[str]
) -> Tuple[List[Path], List[Path]]:
    to_apply: List[Path] = []
    skipped: List[Path] = []
    for path in all_files:
        if path.name in applied_filenames:
            skipped.append(path)
        else:
            to_apply.append(path)
    return to_apply, skipped


def _safe_error_message(err: Exception) -> str:
    msg = str(err) or err.__class__.__name__
    msg = msg.split("\n")[0]
    msg = re.sub(r"postgresql?://\S+", "<redacted>", msg)
    return msg[:300]


def _require_env_vars(names: Iterable[str]) -> Dict[str, str]:
    missing = [name for name in names if not os.environ.get(name)]
    if missing:
        print(
            f"Error: Missing required env vars: {', '.join(missing)}",
            file=sys.stderr,
        )
        raise SystemExit(1)
    return {name: os.environ[name] for name in names}


def _load_connection_info() -> Dict[str, str]:
    # Required for Supabase environment validation (even if not used directly)
    _require_env_vars(["SUPABASE_URL", "SUPABASE_SERVICE_ROLE_KEY"])

    dsn = os.environ.get("DATABASE_URL") or os.environ.get("SUPABASE_DB_URL")
    if dsn:
        return {"dsn": dsn}

    pg_env = _require_env_vars(
        ["PGHOST", "PGPORT", "PGDATABASE", "PGUSER", "PGPASSWORD"]
    )
    return {
        "host": pg_env["PGHOST"],
        "port": pg_env["PGPORT"],
        "dbname": pg_env["PGDATABASE"],
        "user": pg_env["PGUSER"],
        "password": pg_env["PGPASSWORD"],
    }


def _import_psycopg():
    try:
        import psycopg  # type: ignore

        return psycopg
    except Exception:
        try:
            import psycopg2 as psycopg  # type: ignore

            return psycopg
        except Exception:
            print(
                "Error: psycopg (v3) or psycopg2 is required to run migrations.",
                file=sys.stderr,
            )
            raise SystemExit(1)


def _open_connection(conn_info: Dict[str, str]):
    psycopg = _import_psycopg()
    if "dsn" in conn_info:
        conn = psycopg.connect(conn_info["dsn"])
    else:
        conn = psycopg.connect(
            host=conn_info["host"],
            port=conn_info["port"],
            dbname=conn_info["dbname"],
            user=conn_info["user"],
            password=conn_info["password"],
        )
    if hasattr(conn, "autocommit"):
        conn.autocommit = False
    return conn


def _ensure_schema_migrations_table(conn) -> None:
    sql = """
    create table if not exists public.schema_migrations (
      filename text primary key,
      applied_at timestamptz default now(),
      checksum text null
    );
    """
    with conn.cursor() as cur:
        cur.execute(sql)
    conn.commit()


def _fetch_applied_migrations(conn) -> Dict[str, Optional[str]]:
    with conn.cursor() as cur:
        cur.execute("select filename, checksum from public.schema_migrations")
        rows = cur.fetchall()
    return {row[0]: row[1] for row in rows}


def _requires_autocommit(sql: str) -> bool:
    return any(pattern.search(sql) for pattern in AUTOCOMMIT_STATEMENTS)


def _apply_migration(conn, path: Path, checksum: str) -> None:
    sql = path.read_text(encoding="utf-8")
    if CONCURRENT_INDEX_RE.search(sql) or CONCURRENT_DROP_INDEX_RE.search(sql):
        raise RuntimeError(
            f"{path.name} uses CREATE/DROP INDEX CONCURRENTLY. "
            "This runner does not support CONCURRENTLY; apply manually."
        )

    needs_autocommit = _requires_autocommit(sql)

    if needs_autocommit and hasattr(conn, "autocommit"):
        conn.autocommit = True

    try:
        with conn.cursor() as cur:
            cur.execute(sql)
    finally:
        if needs_autocommit and hasattr(conn, "autocommit"):
            conn.autocommit = False

    # Track applied migration in a separate transaction
    with conn.cursor() as cur:
        cur.execute(
            """
            insert into public.schema_migrations (filename, checksum)
            values (%s, %s)
            on conflict (filename) do nothing
            """,
            (path.name, checksum),
        )
    conn.commit()


def _print_summary(applied: List[str], skipped: List[str]) -> None:
    print("")
    print("Summary")
    print(f"Applied: {len(applied)}")
    print(f"Skipped: {len(skipped)}")
    if applied:
        print("Applied migrations:")
        for name in applied:
            print(f"- {name}")
    if skipped:
        print("Skipped migrations:")
        for name in skipped:
            print(f"- {name}")


def main() -> int:
    repo_root = Path(__file__).resolve().parents[1]
    migrations_dir = repo_root / "supabase" / "migrations"

    try:
        migration_files = discover_migration_files(migrations_dir)
    except FileNotFoundError as err:
        print(f"Error: {err}", file=sys.stderr)
        return 1

    if not migration_files:
        print("No migrations found.")
        return 0

    conn_info = _load_connection_info()
    conn = _open_connection(conn_info)

    applied: List[str] = []
    skipped: List[str] = []

    try:
        _ensure_schema_migrations_table(conn)
        applied_map = _fetch_applied_migrations(conn)
        to_apply, skipped_paths = plan_migrations(
            migration_files, set(applied_map.keys())
        )

        skipped = [path.name for path in skipped_paths]
        for path in skipped_paths:
            stored_checksum = applied_map.get(path.name)
            if stored_checksum and stored_checksum != compute_checksum(path):
                print(
                    f"Warning: checksum mismatch for already-applied migration {path.name}.",
                    file=sys.stderr,
                )

        for path in to_apply:
            checksum = compute_checksum(path)
            print(f"Applying {path.name}...")
            try:
                _apply_migration(conn, path, checksum)
            except Exception as err:
                conn.rollback()
                print(
                    f"Error applying {path.name}: {_safe_error_message(err)}",
                    file=sys.stderr,
                )
                return 1
            applied.append(path.name)

        _print_summary(applied, skipped)
        return 0
    finally:
        try:
            conn.close()
        except Exception:
            pass


if __name__ == "__main__":
    raise SystemExit(main())

