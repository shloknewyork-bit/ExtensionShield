# Scripts

Use these when you need to run something outside the usual `make` targets (e.g. deploy, migrations, or one-off tasks). Prefer **Make** when possible: `make api`, `make deploy`, `make migrate`, etc.

## How to run (Make)

| What you want | Command |
|---------------|---------|
| Start API | `make api` |
| Check Railway env before deploy | `make deploy-check` |
| Deploy to Railway | `make deploy` |
| Run Supabase migrations | `make migrate` |
| Clear all scans (Cloud only) | `make clear-scans` |
| Check Postgres connection (Cloud) | `make validate-postgres` |

---

## What each script does

**Start / deploy**

- **start_api.sh** — Starts the API (used by Docker). You can run `make api` instead for local dev.
- **deploy.sh** — Pushes the app to Railway. Same as `make deploy`.
- **check_railway_env.sh** — Makes sure required env vars are set for Railway. Run before deploying.
- **sync_railway_env.sh** — Copies env from your `.env` into the Railway project. Handy after adding new keys.

**Supabase / database**

- **supabase_push_env.sh** — Pushes schema and env to Supabase (staging or prod). Run once per environment when you change migrations.
- **cloud_only/run_supabase_migrations.py** — Applies SQL migrations (used at startup when Supabase is configured, or in CI).
- **cloud_only/validate_postgres_local.py** — Checks that local dev is talking to the right Supabase DB. `make validate-postgres`.
- **cloud_only/lint_migrations.py** — Checks migration file names and order. `make lint-migrations`.
- **cloud_only/clear_all_scans.py** — Deletes every scan from the DB. Cloud only. `make clear-scans`.
- **cloud_only/delete_scans_before_extension.py** — Deletes scans for a given extension (admin cleanup). Run with `PYTHONPATH=src python scripts/cloud_only/delete_scans_before_extension.py "Extension Name"`.

**Security / CSP**

- **setup-production-csp.sh** — Builds the frontend and configures CSP headers for production.
- **verify-csp.sh** — Checks that CSP is correct (dev or prod). Run after changing headers.
- **security_smoke.sh** — Quick security checks. Run by hand when you want a sanity check.

**Auth / email (Cloud dev)**

- **send-resend-test-email.mjs** — Sends a test email via Resend. `npm run resend:test` or `node scripts/send-resend-test-email.mjs`.
- **debug-magic-link.mjs** — Helps debug magic-link sign-in. `node scripts/debug-magic-link.mjs your@email.com`.
- **supabase-set-smtp.mjs** — Configures SMTP in Supabase for auth emails. Run from project root when setting up a new project.

**Other**

- **generate_hero_snapshot.js** — Regenerates the hero carousel data from the API. Run from root: `node scripts/generate_hero_snapshot.js`. Frontend reads from `frontend/src/data/heroSnapshot.js`.
- **benchmark_scanners.py** — Export ExtensionShield scan data (and optionally CRXplorer/Extension Auditor) for benchmarking. From root: `uv run python scripts/benchmark_scanners.py --output data/scanner_benchmark.json`. Use `--crxplorer` to fetch CRXplorer per extension; use `--from-excel docs/qa_extensionshield/qa_scoring_export.xlsx` to run against the same extension list as the QA Excel (ensures alignment with Supabase and Excel).
- **export_qa_scoring_excel.py** — Exports all completed scans from the database to Excel for QA and Crxplorer comparison. Writes to `docs/qa_extensionshield/qa_scoring_export.xlsx` by default. From root: `uv run python scripts/export_qa_scoring_excel.py`. Use `--all` to include every completed scan (ignore visibility/source filter). Use `--out path.xlsx` to override output path.
- **fetch_extensionauditor_bulk.py** — Fetches ExtensionAuditor bulk-analysis results for extensions in the QA export and merges them into the Excel. Set `EXTENSIONAUDITOR_API_KEY` in the environment (or `.env`), then from root: `uv run python scripts/fetch_extensionauditor_bulk.py`. Updates the export in place and writes a finalized report to `docs/qa_extensionshield/qa_scoring_final.xlsx`. Use `--limit N` to process only N extensions; use `--no-in-place` to only write the output file without modifying the export.
- **fetch_extensionauditor_scrape.py** — **Scrape** Extension Auditor’s scan page with a real browser (Playwright): open their site, enter each extension URL, run scan, and extract risk/verdict. Use when the API returns 500 or is unavailable. From root: `uv run python scripts/fetch_extensionauditor_scrape.py` (optional: `--limit 5 --headed`). Requires Playwright: `uv sync --group dev` then `playwright install chromium`. `--headed` shows the browser and often helps avoid Cloudflare blocks.
- **qa_verify_scoring_from_excel.py** — Reads the QA export Excel, fetches each extension’s Chrome Web Store listing, and produces a verification report (name check, our score vs store rating/users). From root: `uv run python scripts/qa_verify_scoring_from_excel.py` (optional: `--limit 5`, `--out docs/qa_extensionshield/qa_scoring_verification_report.md`).
- **qa_regression_scoring.py** — Compares a baseline list (CSV or Excel) to the current export to detect missing extensions or score/decision changes. From root: `uv run python scripts/qa_regression_scoring.py --baseline docs/qa_extensionshield/qa_scoring_verification_report.csv --current docs/qa_extensionshield/qa_scoring_export.xlsx` (add `--strict` to fail on score/decision changes).

---

## Running scripts directly

Start API (same as Docker):

```bash
./scripts/start_api.sh
```

Check Railway env:

```bash
./scripts/check_railway_env.sh
```

Deploy:

```bash
./scripts/deploy.sh
```

Supabase schema push (staging vs prod):

```bash
./scripts/supabase_push_env.sh prod
# or with staging ref:
SUPABASE_STAGING_REF=your-ref ./scripts/supabase_push_env.sh staging
```

CSP (after changing headers):

```bash
./scripts/setup-production-csp.sh
./scripts/verify-csp.sh
```
