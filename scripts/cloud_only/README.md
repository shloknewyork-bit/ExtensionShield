# Cloud-Only Scripts

These scripts require `EXTSHIELD_MODE=cloud` and Supabase credentials.
They are not needed for OSS mode.

| Script | Purpose |
|--------|---------|
| `clear_all_scans.py` | Delete all scan results from database |
| `delete_scans_before_extension.py` | Prune old scans |
| `run_supabase_migrations.py` | Apply Supabase SQL migrations |
| `validate_postgres_local.py` | Verify Supabase connection |
| `lint_migrations.py` | Lint migration file naming |

## Usage

```bash
EXTSHIELD_MODE=cloud python scripts/cloud_only/clear_all_scans.py
```
