#!/usr/bin/env python3
"""
Clear all scan results from the database. Statistics/counter go to 0.
Use this to start fresh with the same schema.

Usage (from project root):
  PYTHONPATH=src python3 scripts/clear_all_scans.py

SQLite: deletes all rows from scan_results and updates the statistics table to 0.
Supabase: deletes all rows from scan_results (stats are computed from rows, so they become 0).

To clear production: set DB_BACKEND=supabase and ensure .env has
SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY for the prod project, then run.
"""

from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if (PROJECT_ROOT / ".env").exists():
    try:
        from dotenv import load_dotenv
        load_dotenv(PROJECT_ROOT / ".env")
    except ImportError:
        pass
sys.path.insert(0, str(PROJECT_ROOT / "src"))


def main() -> int:
    from extension_shield.api.database import db

    ok = db.clear_all_results()
    if ok:
        print("All scan results cleared. Counter is 0.")
        return 0
    print("Clear failed.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
