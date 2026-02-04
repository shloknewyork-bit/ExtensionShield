### Persistence & Storage Audit (ExtensionShield)

Scope: backend persistence/storage paths (extension artifacts, JSON backups, DBs) and env vars used today.

---

### Where we write/read extension artifacts (CRX/ZIP + extracted directories)

- **Download (Chrome Web Store → `.crx`)**: `src/extension_shield/core/extension_downloader.py`
  - **Write**: streams to `<EXTENSION_STORAGE_PATH>/<extension_id>.crx`
  - **Delete on validation failure**: removes the file if too small / invalid

- **Download (chrome-stats.com → `.zip`/`.crx`)**: `src/extension_shield/core/chromestats_downloader.py`
  - **Write**: downloads to `<EXTENSION_STORAGE_PATH>/<name>_<extension_id>_<version>.{zip|crx}`

- **Upload (user-provided `.crx`/`.zip` via API)**: `src/extension_shield/api/main.py`
  - **Write**: saves uploaded bytes to `<RESULTS_DIR>/<uuid>_<original_filename>` (RESULTS_DIR is derived from `EXTENSION_STORAGE_PATH`)

- **Extraction (`.crx`/`.zip` → extracted dir)**: `src/extension_shield/utils/extension.py` (`extract_extension_crx`)
  - **Write**: creates `<EXTENSION_STORAGE_PATH>/extracted_<basename>_<pid>/`
  - **Write**: creates `<extract_dir>/temp.zip` for `.crx` (after header skip), then `zipfile.extractall(extract_dir)`
  - **Delete**: removes `<extract_dir>/temp.zip` after extraction

- **Cleanup (downloaded artifact only; extracted dir is retained)**:
  - **Workflow cleanup**: `src/extension_shield/workflow/nodes.py` (`cleanup_node`)
    - **Keeps extracted dir** for file viewing
    - **Deletes downloaded CRX** via `cleanup_downloaded_crx()` if the tool downloaded it
  - **Safe delete helper**: `src/extension_shield/utils/extension.py` (`cleanup_downloaded_crx`)
    - **Delete**: `os.remove(crx_file_path)` only if within `EXTENSION_STORAGE_PATH`

- **Read extracted files (for UI file viewer + icons)**: `src/extension_shield/api/main.py`
  - **Read**: directory walk (`os.walk`) for file list
  - **Read**: file content (`open(full_path, "r")`) with path traversal guard
  - **Read**: extension icons via `FileResponse(icon_path)` and manifest-based lookup

---

### Where we write/read scan results JSON backups

- **Write backup results JSON**: `src/extension_shield/api/main.py` (`run_analysis_workflow`)
  - **Write**: `<RESULTS_DIR>/<extension_id>_results.json` via `json.dump(...)`

- **Read backup results JSON (fallback)**: `src/extension_shield/api/main.py`
  - **Read**: `<RESULTS_DIR>/<extension_id>_results.json` via `json.load(...)` in multiple fallback paths when memory/DB miss

- **Tests/fixtures consume `_results.json` snapshots**: `tests/fixtures/*_results.json`, `tests/test_golden_snapshots.py`
  - These are **test inputs**, not produced by the runtime pipeline.

---

### Database persistence (SQLite / Supabase)

- **SQLite (default)**: `src/extension_shield/api/database.py` (`Database`)
  - **DB file path**: `DATABASE_PATH` (default: `project-atlas.db`)
  - **Write**: `save_scan_result()` inserts/replaces into `scan_results`
  - **Read**: `get_scan_result()`, `get_scan_history()`, `get_statistics()`, etc.

- **Supabase (optional, when configured)**: `src/extension_shield/api/database.py` (`SupabaseDatabase`)
  - **Enabled when**: `SUPABASE_URL` + (`SUPABASE_SERVICE_ROLE_KEY` or `SUPABASE_ANON_KEY`) are set
  - **Table**: `SUPABASE_SCAN_RESULTS_TABLE` (default: `scan_results`)
  - **Write**: upsert by `extension_id`
  - **Read**: select/history/stats computed from fetched rows
  - **Fallback**: if Supabase init fails, code falls back to SQLite

---

### Governance stage JSON outputs (write-capable, not used by API pipeline today)

These modules provide `save(..., output_path)` helpers that write JSON files, but the FastAPI scan workflow currently keeps governance outputs in memory / DB payloads.

- `src/extension_shield/governance/facts_builder.py` → facts.json
- `src/extension_shield/governance/evidence_index_builder.py` → evidence_index.json
- `src/extension_shield/governance/signal_extractor.py` → signals.json
- `src/extension_shield/governance/store_listing_extractor.py` → store_listing.json
- `src/extension_shield/governance/context_builder.py` → context.json
- `src/extension_shield/governance/report_generator.py` → report.json (+ optional report.html)

---

### Env vars used today (backend)

#### Persistence/storage + DB
- **`EXTENSION_STORAGE_PATH`**: filesystem root for downloads, extracted dirs, and API JSON backups
- **`DATABASE_PATH`**: SQLite DB path
- **`SUPABASE_URL`**
- **`SUPABASE_SERVICE_ROLE_KEY`** (preferred server-side) or **`SUPABASE_ANON_KEY`**
- **`SUPABASE_SCAN_RESULTS_TABLE`**: override table name (default: `scan_results`)

#### Scan pipeline (non-persistence but used during analysis)
- **`CHROME_VERSION`**: CWS CRX download URL construction
- **`CHROMESTATS_API_KEY`**, **`CHROMESTATS_API_URL`**
- **`VIRUSTOTAL_API_KEY`**

#### LLM integration (non-persistence)
- **`LLM_PROVIDER`**, **`LLM_MODEL`**
- **`OPENAI_API_KEY`**
- **`RITS_API_BASE_URL`**, **`RITS_API_KEY`**
- **`WATSONX_API_ENDPOINT`**, **`WATSONX_PROJECT_ID`**, **`WATSONX_API_KEY`**

---

### Centralized config implementation

Implemented in `src/extension_shield/core/config.py`:
- **ENV**: `ENV` / `APP_ENV` / `EXTENSION_SHIELD_ENV` → `local|dev|prod` (default `local`)
- **STORAGE_BACKEND**: `STORAGE_BACKEND` → `local|supabase` (default `local`)
- **DB_BACKEND**:
  - Auto: `supabase` if Supabase creds exist, else `sqlite` (current behavior)
  - Optional override: `DB_BACKEND=sqlite|supabase|postgres` (postgres is explicitly unsupported today)
- **Paths**: exposes `.paths.storage_root` (raw) and `.paths.results_dir` (absolute, matches API behavior)
- **Prod validation**: if ENV resolves to `prod`, requires explicit `EXTENSION_STORAGE_PATH`, and DB-specific requirements


