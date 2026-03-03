# Security Policy

## Reporting a Vulnerability

**Please do NOT open a public GitHub issue for security vulnerabilities.**

If you discover a security vulnerability in ExtensionShield, please report it
responsibly via one of these channels:

- **Email**: [security@extensionshield.com](mailto:security@extensionshield.com)
- **GitHub Security Advisory**: Use the "Report a vulnerability" button on the
  [Security tab](../../security/advisories/new) of this repository.

### What to include

- A description of the vulnerability and its potential impact.
- Steps to reproduce (proof of concept if possible).
- Any relevant logs, screenshots, or configuration details.

### What to expect

| Step | Timeline |
|------|----------|
| Acknowledgement of report | Within 48 hours |
| Initial assessment | Within 5 business days |
| Fix or mitigation plan shared | Within 15 business days |
| Public disclosure (coordinated) | After fix is released |

We will credit reporters in the release notes unless they prefer anonymity.

## Supported Versions

| Version | Supported |
|---------|-----------|
| Latest `main` | Yes |
| Older releases | Best-effort only |

## Security Best Practices for Contributors

- **Never commit secrets.** API keys, passwords, tokens, and private keys must
  never appear in source code or git history. Use `.env` files (gitignored) and
  reference `.env.example` for the expected variable names.
- **Use pre-commit hooks.** This repo includes a gitleaks pre-commit hook that
  blocks commits containing secrets. Run `pre-commit install` after cloning.
- **Run `make secrets-check` before pushing.** This checks that `.env` is not
  committed and, if gitleaks is installed, scans for leaked secrets. See Makefile.
- **Rotate compromised keys immediately.** If a key is accidentally committed,
  rotate it in the provider's dashboard, purge from git history with
  `git filter-repo`, and notify the maintainers. See
  [docs/HISTORY_CLEANUP_AND_ROTATION.md](docs/HISTORY_CLEANUP_AND_ROTATION.md) for exact steps.
- **Keep dependencies updated.** CI runs `pip-audit` and `npm audit`
  automatically. Address high/critical findings promptly.
