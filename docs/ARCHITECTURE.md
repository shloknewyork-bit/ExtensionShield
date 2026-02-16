# ExtensionShield Architecture & Clean-up Guide

## Backend ( `src/` )

- **FastAPI entry points**: `api/main.py` wires the scan trigger, file upload, scan-status, and governance APIs. Each route delegates to well-tested services (`ReportGenerator`, `ScoringEngine`, `SignalPackBuilder`) and uses shared helpers so the handler stays concise.
- **Payload helpers**: `api/payload_helpers.py` centralizes legacy upgrades, scoring/report-model rebuilding, and consumer-insights computation. Import and reuse `upgrade_legacy_payload`, `ensure_consumer_insights`, and `log_scan_results_return_shape` wherever you need consistent payload shapes.
- **Database + governance**: `database.py` exposes `db` plus Supabase adapters while governance code (e.g., `governance/tool_adapters.py`, `workflow/`) keeps the analysis, scoring, and rules orthogonal.
- **Logging + monitoring**: The backend logs payload shapes and upgrade outcomes centrally so engineers can reason about scoring drift without touching every endpoint. Keep new code behind helper functions to avoid duplicating the logging and upgrade criteria seen in `payload_helpers.py`.

## Frontend ( `frontend/src/` )

- **Service helpers**: `services/requestHelpers.js` standardizes JSON parsing and error construction so services like `realScanService.js` and `databaseService.js` can reuse `fetchJson` + `buildFetchError` instead of re-implementing try/catch logic.
- **Reusable UI primitives**: The `components/ui` directory contains buttons, cards, dialogs, and badges. When building new layout or modal components, compose these primitives instead of repeating `className` strings. Keep style variants in one place (e.g., `buttonVariants` in `ui/button.jsx`).
- **Scanner/report flow**: The scanner pages (`pages/scanner/`) consume normalized scan payloads from the backend (via `services/realScanService`). Each report nugget (donut, risk dial, evidence drawer) should rely on shared utility functions (`utils/`) for normalization, translation, and risk-band lookups.

## Cleanup Best Practices

1. **DRY helpers first**: Whenever you see repeated fetch logic, message parsing, or layout markup, extract it into `services/requestHelpers.js` or a new UI primitive. Aim for a 1:1 mapping between concerns (network vs. presentation) so future cleanup is easier.
2. **Document new patterns**: After adding shared helpers or components, update this doc (or add a sibling under `docs/`) describing where to find them and how to reuse them.
3. **Keep API/UX aligned**: The backend upgrade helpers ensure the frontend sees a consistent `report_view_model`/`scoring_v2`. If you change the payload format, update the helper in `api/payload_helpers.py`, re-run the scoring pipeline, and mention the change here so downstream UI code knows to expect new fields.
4. **Safe logging and errors**: Always return structured errors (with `status`/`detail`) so the frontend `buildFetchError` helper can display meaningful messages without duplicating the translation logic.

## Next Cleanup Focus Suggestions

- Split very large backend files (e.g., `extension_shield/api/main.py` still contains many route handlers) by moving route logic into dedicated routers or service modules.
- Introduce shared layout modules for the scanner/report flows (`ScannerLayout`, `ReportSection`) to reduce duplicate JSX and class names.
- Add more inline documentation to complex helpers such as `SignalPackBuilder` and `ScoringEngine` so they are easier to reuse when building new scans or governance rules.
