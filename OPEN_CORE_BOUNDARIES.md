# Open-Core Boundaries

ExtensionShield is **open-core**: the scanner, CLI, and local analysis are **MIT-licensed** and fully functional without any cloud. Cloud features (auth, history, team dashboards, community queue, enterprise forms) are **gated** and disabled by default.

## OSS vs Cloud

| Mode | Default | What runs |
|------|---------|-----------|
| **OSS** (`EXTSHIELD_MODE=oss`) | Yes | Scanner, CLI, SQLite, report UI. No cloud calls. |
| **Cloud** (`EXTSHIELD_MODE=cloud`) | No | All of the above + Supabase, auth, history, telemetry admin, community queue, enterprise/careers. |

## Cloud endpoints in OSS mode

When running in OSS mode, **cloud-only API routes return HTTP 501** with a JSON body:

```json
{"detail": {"error": "not_implemented", "feature": "<name>", "mode": "oss"}}
```

They do **not** run cloud logic or call Supabase. The boundary is enforced in code (e.g. `require_cloud_dep("feature_name")` on FastAPI routes).

Examples of gated features: user history, karma, telemetry summary, review queue, pilot/careers forms. Scan, report, feedback, and health endpoints work in both modes.

## Configuration

- **Backend:** `EXTSHIELD_MODE` (default `oss`). Optional flags: `AUTH_ENABLED`, `HISTORY_ENABLED`, `TELEMETRY_ENABLED`, etc. See `.env.example` and `src/extension_shield/utils/mode.py`.
- **Frontend:** `VITE_AUTH_ENABLED` (default `false`) — when false, auth/history UI is not used and the scanner works without sign-in.

## Summary

- **OSS** = everything you need to run and verify the trust layer locally; no cloud required.
- **Cloud** = optional hosted product (ExtensionShield Cloud) using the same codebase with Supabase and extra features; those features return 501 when the app is run in OSS mode.

For full setup and configuration options, see [GET_STARTED.md](GET_STARTED.md).
