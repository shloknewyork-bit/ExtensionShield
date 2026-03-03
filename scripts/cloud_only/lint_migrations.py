#!/usr/bin/env python3
"""
Lint Supabase migrations for filename patterns, ordering, and unsafe statements.
Uses supabase/migrations/ with Supabase CLI timestamp format (14-digit prefix).
"""

from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import List, Sequence, Tuple


# Supabase CLI format: 20260205000000_scan_results.sql
MIGRATION_FILENAME_RE = re.compile(r"^\d{14}_.*\.sql$")
# At least the first scan_results migration must exist
REQUIRED_MIGRATIONS = {
    "20260205000000_scan_results.sql",
}
CONCURRENTLY_RE = re.compile(r"\bCONCURRENTLY\b", re.IGNORECASE)


def _migration_sort_key(name: str) -> Tuple[int, str]:
    match = re.match(r"^(\d{14})_", name)
    if not match:
        return (10**15, name)
    return (int(match.group(1)), name)


def _load_migration_files(migrations_dir: Path) -> List[Path]:
    if not migrations_dir.exists():
        raise FileNotFoundError(f"Migrations directory not found: {migrations_dir}")
    return [path for path in migrations_dir.iterdir() if path.is_file()]


def _validate_filenames(paths: Sequence[Path]) -> List[str]:
    invalid = [path.name for path in paths if not MIGRATION_FILENAME_RE.match(path.name)]
    return sorted(invalid)


def _validate_sorted(names: Sequence[str]) -> Tuple[bool, List[str], List[str]]:
    lex_sorted = sorted(names)
    key_sorted = sorted(names, key=_migration_sort_key)
    return lex_sorted == key_sorted, lex_sorted, key_sorted


def _find_concurrently(paths: Sequence[Path]) -> List[str]:
    offenders: List[str] = []
    for path in paths:
        if not MIGRATION_FILENAME_RE.match(path.name):
            continue
        content = path.read_text(encoding="utf-8")
        if CONCURRENTLY_RE.search(content):
            offenders.append(path.name)
    return sorted(offenders)


def main() -> int:
    repo_root = Path(__file__).resolve().parents[1]
    migrations_dir = repo_root / "supabase" / "migrations"

    errors: List[str] = []
    try:
        files = _load_migration_files(migrations_dir)
    except FileNotFoundError as err:
        errors.append(str(err))
        files = []

    filenames = [path.name for path in files]

    invalid = _validate_filenames(files)
    if invalid:
        errors.append(
            "Invalid migration filenames (must match ^\\d{14}_.*\\.sql$): "
            + ", ".join(invalid)
        )

    duplicates = sorted({name for name in filenames if filenames.count(name) > 1})
    if duplicates:
        errors.append(f"Duplicate migration filenames found: {', '.join(duplicates)}")

    if filenames:
        stable, lex_sorted, key_sorted = _validate_sorted(
            [name for name in filenames if MIGRATION_FILENAME_RE.match(name)]
        )
        if not stable:
            errors.append(
                "Migration sort order is unstable. Expected lexicographic order to "
                "match numeric prefix order.\n"
                f"Lex order: {', '.join(lex_sorted)}\n"
                f"Key order: {', '.join(key_sorted)}"
            )

    missing_required = sorted(REQUIRED_MIGRATIONS - set(filenames))
    if missing_required:
        errors.append(
            "Missing required migrations: " + ", ".join(missing_required)
        )

    concurrently = _find_concurrently(files)
    if concurrently:
        errors.append(
            "Migrations contain CONCURRENTLY (not allowed): "
            + ", ".join(concurrently)
        )

    if errors:
        for err in errors:
            print(f"ERROR: {err}", file=sys.stderr)
        return 1

    print("Migrations lint passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

