<h1 align="center">ExtensionShield</h1>

<p align="center">
  <strong>Chrome Extension Security Scanner & Governance Platform</strong>
</p>

<p align="center">
  Open-core: the scanner, CLI, and local analysis are MIT-licensed and fully functional.<br/>
  Cloud features (auth, history, team monitoring, community queue) are available via
  <a href="https://extensionshield.com">ExtensionShield Cloud</a>.
</p>

**Security Policy**: See [SECURITY.md](SECURITY.md) &nbsp;|&nbsp; **Open-Core Boundaries**: See [docs/OPEN_CORE_BOUNDARIES.md](docs/OPEN_CORE_BOUNDARIES.md)

---

## Quick Start (OSS Mode)

No Supabase keys, no cloud accounts needed. Just an LLM API key for AI summaries.

### Local Development

```bash
# 1. Clone and install
git clone https://github.com/<your-org>/ExtensionShield.git
cd ExtensionShield
make install                    # Python (uv sync)
cd frontend && npm install      # Frontend dependencies

# 2. Configure environment
cp .env.example .env
# Edit .env: add OPENAI_API_KEY (required for AI summaries)
# EXTSHIELD_MODE=oss is the default — no other keys needed

cp frontend/.env.example frontend/.env
# No changes needed for OSS mode

# 3. Start servers (two terminals)
make api                        # Terminal 1: API at http://localhost:8007
make frontend                   # Terminal 2: UI at http://localhost:5173
```

### Docker

```bash
cp .env.example .env
# Edit .env: add your OPENAI_API_KEY
docker compose up --build
# → http://localhost:8007
```

### CLI

```bash
make analyze URL=https://chromewebstore.google.com/detail/example/abcdef
```

---

## What Works in OSS Mode

| Feature | OSS | Cloud |
|---------|-----|-------|
| Scan Chrome Web Store extensions | Yes | Yes |
| Upload & scan CRX/ZIP files | Yes | Yes |
| Security scoring + risk analysis | Yes | Yes |
| SAST, permissions, entropy analysis | Yes | Yes |
| VirusTotal integration | Yes | Yes |
| AI-powered summaries | Yes | Yes |
| CLI analysis | Yes | Yes |
| SQLite local storage | Yes | Yes |
| View scan reports in browser | Yes | Yes |
| Supabase persistence | — | Yes |
| User authentication | — | Yes |
| Scan history per user | — | Yes |
| User karma / reputation | — | Yes |
| Community review queue | — | Yes |
| Telemetry admin dashboard | — | Yes |
| Enterprise pilot forms | — | Yes |

---

## Enabling Cloud Mode

To enable all features, set these in `.env`:

```bash
EXTSHIELD_MODE=cloud
DB_BACKEND=supabase
SUPABASE_URL=https://your-project.supabase.co
SUPABASE_SERVICE_ROLE_KEY=your-service-role-key
```

And in `frontend/.env`:

```bash
VITE_AUTH_ENABLED=true
VITE_SUPABASE_URL=https://your-project.supabase.co
VITE_SUPABASE_ANON_KEY=your-anon-key
```

---

## Make Commands

```bash
make help           # Show all commands
make dev            # Show OSS dev setup instructions
make api            # Start API server (port 8007)
make frontend       # Start React dev server (port 5173)
make analyze URL=   # Analyze extension from URL
make test           # Run tests
make format         # Format code (Black)
make lint           # Lint code (Pylint)
make secrets-check  # Check for accidental committed secrets
```

---

## Documentation

| Document | Description |
|----------|-------------|
| [docs/README.md](docs/README.md) | Documentation index |
| [docs/OPEN_CORE_BOUNDARIES.md](docs/OPEN_CORE_BOUNDARIES.md) | What's OSS vs Cloud |
| [SECURITY.md](SECURITY.md) | Reporting vulnerabilities, secrets policy |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Contribution guidelines |
| [docs/TRADEMARK.md](docs/TRADEMARK.md) | Brand usage guidelines |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | High-level architecture |

---

## License

**Core** (scanner, CLI, local analysis): MIT License — see [LICENSE](LICENSE) for details.

**Cloud features** (auth, Supabase persistence, telemetry admin, community queue, enterprise forms):
proprietary, available via [ExtensionShield Cloud](https://extensionshield.com).

---

## Acknowledgments

ExtensionShield builds on the excellent [ThreatXtension](https://github.com/barvhaim/ThreatXtension) project, extending it with compliance, evidence-oriented layers, and governance.
