<h1 align="center">ExtensionShield</h1>

<p align="center">
  <strong>Enterprise Chrome Extension Security & Governance Platform</strong>
</p>

---

## Quick Start

### Docker (Recommended)

```bash
# 1. Clone the repository
git clone https://github.com/your-org/ExtensionShield.git
cd ExtensionShield

# 2. Configure environment
cp env.production.template .env
# Edit .env and add your OPENAI_API_KEY (required)

# 3. Build and run
docker compose up --build

# 4. Access the application
# → http://localhost:8007
```

### Local Development

```bash
# Install dependencies
make install                    # Python (uv sync)
cd frontend && npm install      # Frontend

# Start servers (two terminals)
make api                        # Terminal 1: API at http://localhost:8007
make frontend                   # Terminal 2: UI at http://localhost:5173
```

---

## Make Commands

```bash
make help           # Show all commands
make api            # Start API server
make frontend       # Start React dev server
make analyze URL=   # Analyze extension from URL
make test           # Run tests
make format         # Format code
make lint           # Lint code
```

---

## Documentation

| Document | Description |
|----------|-------------|
| [docs/PROJECT_SPEC.md](docs/PROJECT_SPEC.md) | Product features, API reference, configuration |
| [docs/GOVERNANCE_ARCHITECTURE_AND_HLD.md](docs/GOVERNANCE_ARCHITECTURE_AND_HLD.md) | Architecture, data contracts, implementation details |
| [AGENTS.md](AGENTS.md) | AI/Agent coding guidelines |
| http://localhost:8007/docs | Interactive API documentation (when running) |

---

## License

MIT License — see [LICENSE](LICENSE) for details.
