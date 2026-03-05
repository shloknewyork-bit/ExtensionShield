# Proprietary threat intel and curated datasets

This directory is reserved for **proprietary** data that is **not** included in the OSS release:

- Known-bad hash databases
- Internal telemetry-derived intel
- Proprietary rulepacks or compliance packs

Do **not** commit any such files here in the public repo. Contents are ignored via `.gitignore`. For OSS, the core uses only the public baseline rulepacks under `src/extension_shield/governance/rulepacks/` (MIT).
