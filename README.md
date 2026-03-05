# ExtensionShield

**Chrome Extension Security Scanner & Governance Platform**

ExtensionShield scans Chrome extensions (from the Web Store or CRX/ZIP uploads), runs security and privacy analysis, and produces risk scores and AI-powered summaries. The **core** (scanner, CLI, local analysis) is **MIT-licensed** and works without any cloud. Optional **cloud** features (auth, history, team monitoring, community queue) are available via [ExtensionShield Cloud](https://extensionshield.com).

- **Security:** [SECURITY.md](SECURITY.md) — Reporting vulnerabilities, secrets policy  
- **Open-core:** [OPEN_CORE_BOUNDARIES.md](OPEN_CORE_BOUNDARIES.md) — What’s OSS vs Cloud and how it’s enforced  

---

## Quick start

1. **Clone and install**
   ```bash
   git clone https://github.com/<your-org>/ExtensionShield.git
   cd ExtensionShield
   make install && cd frontend && npm install
   ```
2. **Configure**
   ```bash
   cp .env.example .env
   # Add OPENAI_API_KEY in .env (for AI summaries). OSS mode is the default.
   cp frontend/.env.example frontend/.env
   ```
3. **Run**
   ```bash
   make api      # Terminal 1 → http://localhost:8007
   make frontend # Terminal 2 → http://localhost:5173
   ```

Full setup (Docker, CLI, Cloud mode, Make commands): **[GET_STARTED.md](GET_STARTED.md)**.

---

## What ExtensionShield does

- **Scan** extensions from the Chrome Web Store or by uploading CRX/ZIP files  
- **Analyze** permissions, SAST, entropy, and optional VirusTotal integration  
- **Score** security and privacy risk and generate reports  
- **Summarize** findings with an LLM (OpenAI or others)  

In **OSS mode** (default) you get the full scanner, CLI, local SQLite storage, and report UI—no cloud required. **Cloud mode** adds auth, scan history, telemetry, and enterprise features; see [GET_STARTED.md](GET_STARTED.md#enabling-cloud-mode) and [OPEN_CORE_BOUNDARIES.md](OPEN_CORE_BOUNDARIES.md).

---

## Documentation

| Document | Description |
|----------|-------------|
| [GET_STARTED.md](GET_STARTED.md) | Setup, config, Docker, CLI, OSS vs Cloud, Make commands |
| [OPEN_CORE_BOUNDARIES.md](OPEN_CORE_BOUNDARIES.md) | OSS vs Cloud; enforcement; configuration |
| [CONTRIBUTING.md](CONTRIBUTING.md) | How to contribute |
| [SECURITY.md](SECURITY.md) | Reporting vulnerabilities; secrets policy |
| [COMMERCIAL.md](COMMERCIAL.md) | Commercial use (non-binding) |
| [TRADEMARK.md](TRADEMARK.md) | Brand usage guidelines |
| [NOTICE](NOTICE) | Third-party attributions |

---

## License & attribution

- **Core** (scanner, CLI, local analysis): **MIT** — see [LICENSE](LICENSE).  
- **Cloud** (auth, Supabase, telemetry admin, community queue, enterprise forms): **proprietary**, available via [ExtensionShield Cloud](https://extensionshield.com).  

Attribution: [NOTICE](NOTICE). Brand: [TRADEMARK.md](TRADEMARK.md). Commercial use: [COMMERCIAL.md](COMMERCIAL.md) (non-binding).

---

## Community

We build ExtensionShield in the open so security tools stay transparent and inspectable. Feedback, issue reports, and small improvements (docs, tests, rule tweaks) are welcome. If it helps you or your organization, consider contributing a PR, sharing your use case, or supporting the project. We run open-source programs and internships when we can—community support helps keep that going.

**Acknowledgments:** ExtensionShield is our own design; we took inspiration from [ThreatXtension](https://github.com/barvhaim/ThreatXtension) in the same space (extension scanning, VirusTotal integration).
