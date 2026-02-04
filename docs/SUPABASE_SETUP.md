## Supabase setup (production persistence)

The backend already caches results in memory and writes to a local SQLite DB. In production (e.g. Railway), **local disk can be ephemeral**, so if you want scan history + results to survive redeploys, you should use a persistent store.

This repo supports **Supabase** as an optional storage backend via environment variables.

### 1) Create a table

Run this in the Supabase SQL editor:

```sql
create table if not exists public.scan_results (
  extension_id text primary key,
  extension_name text,
  url text,
  "timestamp" text,
  status text,
  security_score int,
  risk_level text,
  total_findings int default 0,
  total_files int default 0,
  high_risk_count int default 0,
  medium_risk_count int default 0,
  low_risk_count int default 0,
  metadata jsonb,
  manifest jsonb,
  permissions_analysis jsonb,
  sast_results jsonb,
  webstore_analysis jsonb,
  summary jsonb,
  extracted_path text,
  extracted_files jsonb,
  error text,
  created_at timestamptz default now(),
  updated_at timestamptz default now()
);

create index if not exists scan_results_timestamp_idx
  on public.scan_results ("timestamp");
```

Notes:
- We store `"timestamp"` as text because the current app already emits ISO strings; you can change it to `timestamptz` later if you want.
- This schema matches the keys sent by `SupabaseDatabase.save_scan_result()` (upsert).

### 2) Set environment variables (server-side)

Set these in Railway (or your hosting provider):

- `SUPABASE_URL`
- `SUPABASE_SERVICE_ROLE_KEY` (**server only**)
- (optional) `SUPABASE_SCAN_RESULTS_TABLE` (defaults to `scan_results`)

When these are present, the backend will automatically use Supabase instead of SQLite.

### 3) (Optional, recommended) Create a Supabase Storage bucket for artifacts

If you want to persist **downloaded CRX/ZIP artifacts** and/or **extracted extension directories**
across deploys, create a private bucket:

- Supabase Dashboard → Storage → Create bucket
- Name: `extensionshield`
- Visibility: private

Note: the current backend still stores artifacts on the local filesystem (`EXTENSION_STORAGE_PATH`).
Persisting artifacts to Supabase Storage (and generating signed URLs) is a follow-up change.

### 3) Do I need to store results on live?

If you want:
- scan history to show up after a redeploy/restart
- old report pages to keep working

…then **yes**, you need persistent storage (Supabase/Postgres, or a persistent disk volume). Otherwise, only in-memory cache + ephemeral filesystem data may be lost.


