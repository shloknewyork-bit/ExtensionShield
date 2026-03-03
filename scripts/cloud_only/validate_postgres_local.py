#!/usr/bin/env python3
"""
Validate that local dev is pulling data from Supabase Postgres.

Queries scan_results directly to confirm connection and schema consistency.
Run after: DB_BACKEND=supabase, SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY in .env

Usage:
  python scripts/validate_postgres_local.py
  make validate-postgres

  Optional: count rows for a specific extension (e.g. before/after scan):
  VALIDATE_EXTENSION_ID=<extension_id> python scripts/validate_postgres_local.py
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

# Load .env from project root
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if (PROJECT_ROOT / ".env").exists():
    from dotenv import load_dotenv
    load_dotenv(PROJECT_ROOT / ".env")


def main() -> int:
    url = os.environ.get("SUPABASE_URL")
    key = os.environ.get("SUPABASE_SERVICE_ROLE_KEY")
    if not url or not key:
        print("❌ SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY must be set.")
        print("   Add them to .env and set DB_BACKEND=supabase for local dev.")
        return 1

    try:
        from supabase import create_client
    except ImportError:
        print("❌ supabase package not installed. Run: uv sync")
        return 1

    client = create_client(url, key)
    table = os.environ.get("SUPABASE_SCAN_RESULTS_TABLE", "scan_results")

    # 1. Query scan_results (same schema as prod)
    print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    print(f"  Validating Supabase Postgres (table: {table})")
    print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

    resp = (
        client.table(table)
        .select("extension_id, extension_name, risk_level, scanned_at, status, total_findings", count="exact")
        .order("scanned_at", desc=True)
        .limit(10)
        .execute()
    )
    rows = getattr(resp, "data", None) or []
    total = getattr(resp, "count", None)
    if total is None:
        total = f"{len(rows)}+" if len(rows) >= 10 else str(len(rows))

    print(f"\n✓ Connected to Postgres. scan_results: {total} row(s)\n")

    if not rows:
        print("  (No rows yet. Run a scan or apply seed migration to add sample data.)")
        return 0

    print("  Sample rows (most recent first):")
    print("  " + "-" * 72)
    for r in rows:
        ext_id = (r.get("extension_id") or "")[:24] + ".." if len(r.get("extension_id") or "") > 24 else (r.get("extension_id") or "")
        name = (r.get("extension_name") or "")[:30] + ".." if len(r.get("extension_name") or "") > 30 else (r.get("extension_name") or "")
        risk = r.get("risk_level") or "—"
        scanned = r.get("scanned_at") or "—"
        status = r.get("status") or "—"
        findings = r.get("total_findings") or 0
        print(f"  {ext_id:28} | {name:32} | {risk:6} | {findings:3} findings | {scanned[:19] if isinstance(scanned, str) and len(scanned) >= 19 else scanned}")
    print("  " + "-" * 72)
    print("\n✓ Postgres schema consistent. Local dev can validate against prod.")

    # 2. Same query shape as GET /api/recent (used by /scan and /scan/history)
    recent = (
        client.table(table)
        .select("extension_id, extension_name, scanned_at, status, risk_level")
        .eq("status", "completed")
        .order("scanned_at", desc=True)
        .limit(25)
        .execute()
    )
    recent_rows = getattr(recent, "data", None) or []
    print(f"\n✓ get_recent_scans equivalent: {len(recent_rows)} completed rows (limit 25).")
    print("  /scan and /scan/history read from this same Postgres source in prod.")
    print("\n  To confirm via API: start backend then curl http://localhost:8007/api/recent?limit=25")
    print("  Response should include \"db_backend\": \"supabase\" when DB_BACKEND=supabase.")

    # 3. Optional: count rows for a specific extension_id (e.g. before/after scan)
    check_id = os.environ.get("VALIDATE_EXTENSION_ID")
    if check_id:
        count_resp = (
            client.table(table)
            .select("extension_id, extension_name, scanned_at, status", count="exact")
            .eq("extension_id", check_id)
            .execute()
        )
        check_rows = getattr(count_resp, "data", None) or []
        check_count = getattr(count_resp, "count", None) or len(check_rows)
        print(f"\n  Extension ID {check_id}: {check_count} row(s) in scan_results.")
        for r in check_rows:
            print(f"    → {r.get('extension_name') or '—'} | {r.get('scanned_at')} | {r.get('status')}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
