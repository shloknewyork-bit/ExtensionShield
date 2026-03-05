# Get Started with ExtensionShield

This guide walks you through setup, configuration, and daily commands. For a high-level overview, see [README.md](README.md).

---

## Prerequisites

| Tool      | Version  | Purpose                |
|-----------|----------|------------------------|
| Python    | 3.11+    | Backend (FastAPI)      |
| Node.js   | 20+      | Frontend (React/Vite)  |
| [uv](https://docs.astral.sh/uv/) | latest | Python package manager |
| Docker    | latest   | Optional, for full-stack run |

---

## Local Development (OSS Mode)

No Supabase or cloud account required. You only need an LLM API key for AI summaries.

### 1. Clone and install

```bash
git clone https://github.com/<your-org>/ExtensionShield.git
cd ExtensionShield
make install                    # Python (uv sync)
cd frontend && npm install      # Frontend dependencies
```

### 2. Configure environment

**Backend (project root):**

```bash
cp .env.example .env
# Edit .env: add OPENAI_API_KEY (required for AI summaries)
# EXTSHIELD_MODE=oss is the default — no other keys needed for OSS
```

**Frontend:**

```bash
cp frontend/.env.example frontend/.env
# No changes needed for OSS mode
```

### 3. Start servers (two terminals)

```bash
make api      # Terminal 1: API at http://localhost:8007
make frontend # Terminal 2: UI at http://localhost:5173
```

Open the UI at **http://localhost:5173**.

---

## Docker

```bash
cp .env.example .env
# Edit .env: add your OPENAI_API_KEY
docker compose up --build
# → API at http://localhost:8007
```

---

## CLI

Analyze an extension from the Chrome Web Store:

```bash
make analyze URL=https://chromewebstore.google.com/detail/example/abcdef
```

---

## OSS vs Cloud: What Works Where

| Feature                         | OSS | Cloud |
|---------------------------------|-----|-------|
| Scan Chrome Web Store extensions| ✅  | ✅    |
| Upload & scan CRX/ZIP files     | ✅  | ✅    |
| Security scoring + risk analysis | ✅  | ✅    |
| SAST, permissions, entropy      | ✅  | ✅    |
| VirusTotal integration          | ✅  | ✅    |
| AI-powered summaries            | ✅  | ✅    |
| CLI analysis                    | ✅  | ✅    |
| SQLite local storage            | ✅  | ✅    |
| View scan reports in browser    | ✅  | ✅    |
| Supabase persistence            | —   | ✅    |
| User authentication             | —   | ✅    |
| Scan history per user           | —   | ✅    |
| User karma / reputation         | —   | ✅    |
| Community review queue          | —   | ✅    |
| Telemetry admin dashboard       | —   | ✅    |
| Enterprise pilot forms          | —   | ✅    |

See [OPEN_CORE_BOUNDARIES.md](OPEN_CORE_BOUNDARIES.md) for how the boundary is enforced.

---

## Enabling Cloud Mode

To use Supabase, auth, history, and other cloud features:

**In project root `.env`:**

```bash
EXTSHIELD_MODE=cloud
DB_BACKEND=supabase
SUPABASE_URL=https://your-project.supabase.co
SUPABASE_SERVICE_ROLE_KEY=YOUR_SUPABASE_SERVICE_ROLE_KEY_HERE
```

**In `frontend/.env`:**

```bash
VITE_AUTH_ENABLED=true
VITE_SUPABASE_URL=https://your-project.supabase.co
VITE_SUPABASE_ANON_KEY=YOUR_SUPABASE_ANON_KEY_HERE
```

In OSS mode, cloud-only routes return **HTTP 501** with a JSON body indicating the feature is not available. Optional local metrics in OSS: set `OSS_TELEMETRY_ENABLED=true` to store pageview/event in SQLite only (no outbound). Details: [OPEN_CORE_BOUNDARIES.md](OPEN_CORE_BOUNDARIES.md).

---

## Make Commands

| Command              | Description                          |
|----------------------|--------------------------------------|
| `make help`          | Show all commands                    |
| `make dev`           | Show OSS dev setup instructions      |
| `make api`           | Start API server (port 8007)          |
| `make frontend`      | Start React dev server (port 5173)   |
| `make analyze URL=`  | Analyze extension from Chrome Web Store URL |
| `make test`          | Run tests                            |
| `make format`        | Format code (Black)                  |
| `make lint`          | Lint code (Pylint)                   |
| `make secrets-check` | Check for accidental committed secrets |

---

## Pre-commit (recommended)

```bash
pip install pre-commit   # or: uv pip install pre-commit
pre-commit install
```

Hooks include Black, Pylint, gitleaks, and basic file checks. Run `make secrets-check` before pushing.

---

## Next steps

- **Contribute:** [CONTRIBUTING.md](CONTRIBUTING.md)
- **Security:** [SECURITY.md](SECURITY.md)
- **Open-core details:** [OPEN_CORE_BOUNDARIES.md](OPEN_CORE_BOUNDARIES.md)
- **Back to overview:** [README.md](README.md)
