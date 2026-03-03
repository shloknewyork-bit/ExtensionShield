import hashlib
from pathlib import Path

from scripts.cloud_only.run_supabase_migrations import (
    compute_checksum,
    discover_migration_files,
    plan_migrations,
)


def test_discover_migration_files_filters_and_sorts(tmp_path: Path):
    # Valid migrations (Supabase CLI timestamp format: 14 digits + _ + name)
    (tmp_path / "20260205000000_init.sql").write_text("-- init")
    (tmp_path / "20260205000001_rename.sql").write_text("-- rename")
    (tmp_path / "20260206000000_add.sql").write_text("-- add")
    (tmp_path / "20260210193320_more.sql").write_text("-- more")

    # Invalid files (should be ignored)
    (tmp_path / "01_bad.sql").write_text("-- bad")
    (tmp_path / "001_init.sql").write_text("-- old format")
    (tmp_path / "abc.sql").write_text("-- bad")
    (tmp_path / "20260205000000_test.SQL").write_text("-- bad")
    (tmp_path / "20260205000000_init.txt").write_text("-- bad")

    files = discover_migration_files(tmp_path)
    names = [path.name for path in files]

    assert names == [
        "20260205000000_init.sql",
        "20260205000001_rename.sql",
        "20260206000000_add.sql",
        "20260210193320_more.sql",
    ]


def test_compute_checksum_matches_sha256(tmp_path: Path):
    file_path = tmp_path / "20260205000000_init.sql"
    file_path.write_text("select 1;\n")

    expected = hashlib.sha256(file_path.read_bytes()).hexdigest()
    assert compute_checksum(file_path) == expected


def test_plan_migrations_skips_applied(tmp_path: Path):
    all_files = [
        tmp_path / "20260205000000_init.sql",
        tmp_path / "20260205000001_next.sql",
    ]
    to_apply, skipped = plan_migrations(
        all_files, {"20260205000000_init.sql"}
    )

    assert [path.name for path in to_apply] == ["20260205000001_next.sql"]
    assert [path.name for path in skipped] == ["20260205000000_init.sql"]

