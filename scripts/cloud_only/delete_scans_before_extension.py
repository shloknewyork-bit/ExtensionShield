#!/usr/bin/env python3
"""
Delete all scan results that were scanned before the given extension (by name).

Usage (from project root):
  PYTHONPATH=src python3 scripts/delete_scans_before_extension.py "Vertical Tabs in Side Panel"
  PYTHONPATH=src python3 scripts/delete_scans_before_extension.py "Vertical Tabs" --dry-run

To run against production Supabase: set DB_BACKEND=supabase and ensure .env has
SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY for the prod project, then run without --dry-run.

Finds the most recent scan of an extension whose name contains the given string,
then deletes all scan_results with scanned_at before that time. Keeps the
named extension and any scan after it.
"""

from __future__ import annotations

import argparse
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
    parser = argparse.ArgumentParser(description="Delete scans before a given extension (by name).")
    parser.add_argument("name_substring", help="Extension name substring (e.g. 'Vertical Tabs in Side Panel')")
    parser.add_argument("--dry-run", action="store_true", help="Only print what would be deleted")
    args = parser.parse_args()

    from extension_shield.api.database import db

    # Get recent scans so we can find the one matching the name and get its timestamp
    rows = db.get_recent_scans(limit=2000)
    if not rows:
        print("No scan results in database.")
        return 0

    # Find rows matching the name substring; use the most recent (max timestamp) as cutoff
    name_lower = args.name_substring.lower()
    matching = [r for r in rows if (r.get("extension_name") or "").lower().find(name_lower) >= 0]
    if not matching:
        print(f"No extension name containing '{args.name_substring}' found in recent scans.")
        print("Nothing deleted.")
        return 0

    # Cutoff = earliest scanned_at among matching (so we keep that extension and everything after)
    # Rows are ordered by scanned_at DESC, so matching[0] is the most recent scan of that extension.
    cutoff = matching[0].get("timestamp") or matching[0].get("scanned_at")
    if not cutoff:
        print("Could not determine cutoff timestamp.")
        return 1

    # Count how many would be deleted (scanned_at < cutoff)
    before = [r for r in rows if (r.get("timestamp") or r.get("scanned_at") or "") < cutoff]
    to_delete = len(before)

    print(f"Extension '{matching[0].get('extension_name')}' (id={matching[0].get('extension_id')}) has scanned_at = {cutoff}")
    print(f"Scans strictly before that: {to_delete} (from recent {len(rows)} rows; total may be higher)")

    if args.dry_run:
        print("Dry run: no changes made.")
        return 0

    n = db.delete_scans_before(cutoff)
    print(f"Deleted {n} scan result(s) with timestamp before {cutoff}.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
