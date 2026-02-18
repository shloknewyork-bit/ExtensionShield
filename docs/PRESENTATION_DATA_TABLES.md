# ExtensionShield Competitive Benchmark - Presentation Data Tables

**For PowerPoint/Keynote Import**

---

## Table 1: Provider Overview

| Provider | Type | Status | Pricing | Score Format |
|----------|------|--------|---------|--------------|
| ExtensionShield | Enterprise + Consumer | Active | SaaS/API | 0-100 (3 layers) |
| CRXplorer | Consumer | Active | Free + API | AI Risk Score |
| ExtensionAuditor | Consumer + Enterprise | Active | Free + Enterprise | Color Risk Rating |
| ExtensionSecurity.io | Developer | Active | Free | 0-230 + Grade |
| ExtSafe | Consumer | Active | Free | 0-10 |
| CRXaminer | Security Researchers | Active | Free (OSS) | Crit/High/Med/Low |
| CRXcavator | Enterprise | Semi-Active | Free (Legacy) | Quantified Score |

---

## Table 2: Scoring Architecture Comparison

| Provider | Layers | Dimensions | Transparent Weights |
|----------|--------|------------|---------------------|
| **ExtensionShield** | **3** | **14 factors** | **Yes** |
| ExtensionSecurity.io | 1 | 7 | Yes |
| ExtSafe | 1 | 4 | No |
| CRXplorer | 1 | Unknown | No |
| CRXaminer | 1 | Finding-count | Partial |
| CRXcavator | 1 | Permission-based | Partial |
| ExtensionAuditor | 1 | Permission-based | No |

---

## Table 3: Analysis Capabilities Matrix (YES/NO)

| Capability | ExtShield | CRXplorer | ExtAuditor | ExtSec.io | ExtSafe | CRXaminer | CRXcavator |
|------------|:---------:|:---------:|:----------:|:---------:|:-------:|:---------:|:----------:|
| Permission Analysis | YES | YES | YES | YES | YES | YES | YES |
| CSP Evaluation | YES | YES | ? | Partial | YES | ? | YES |
| SAST (Semgrep) | **YES** | NO | NO | NO | NO | NO | NO |
| VirusTotal | **YES** | NO | NO | NO | NO | NO | NO |
| Obfuscation Detection | YES | ? | ? | YES | YES | ? | ? |
| Vulnerable JS Libs | Partial | ? | ? | YES | ? | ? | YES |
| Privacy Policy Check | YES | ? | ? | YES | ? | ? | YES |
| Governance Layer | **YES** | NO | NO | NO | NO | NO | NO |
| Hard Gates (Auto-Block) | **YES** | NO | NO | NO | NO | NO | NO |
| Enterprise Decisions | YES | ? | YES | ? | ? | ? | ? |
| AI-Powered | NO | YES | ? | NO | NO | YES | NO |
| API Access | Planned | YES | ? | ? | ? | NO | YES |

**Unique to ExtensionShield (BOLD):** SAST, VirusTotal, Governance Layer, Hard Gates

---

## Table 4: ExtensionShield Factor Weights

### Security Layer (50% of overall)

| Factor | Weight | Description |
|--------|--------|-------------|
| SAST (Semgrep) | 30% | Static analysis with 47+ custom rules |
| VirusTotal | 15% | Malware hash detection |
| Obfuscation | 15% | Entropy-based detection |
| Manifest | 10% | CSP, MV2, host permissions |
| ChromeStats | 10% | Behavioral threat intelligence |
| Webstore | 10% | Ratings, users, privacy policy |
| Maintenance | 10% | Update freshness |

### Privacy Layer (30% of overall)

| Factor | Weight | Description |
|--------|--------|-------------|
| NetworkExfil | 35% | Network exfiltration patterns |
| PermissionsBaseline | 25% | High-risk permission count |
| PermissionCombos | 25% | Dangerous combinations |
| CaptureSignals | 15% | Screenshot/tab capture |

### Governance Layer (20% of overall)

| Factor | Weight | Description |
|--------|--------|-------------|
| ToSViolations | 50% | Terms of service violations |
| Consistency | 30% | Purpose vs behavior alignment |
| DisclosureAlignment | 20% | Privacy policy vs actual collection |

---

## Table 5: Hard Gates (Auto-BLOCK Triggers)

| Gate ID | Trigger Condition | Action | Penalty |
|---------|-------------------|--------|---------|
| VT_MALWARE | ≥5 malicious VT detections | BLOCK | -45 Security |
| CRITICAL_SAST | ≥1 critical OR ≥3 high findings | BLOCK | -50 Security |
| TOS_VIOLATION | Prohibited perms / automation | BLOCK | -60 Governance |
| PURPOSE_MISMATCH | Credential/tracking patterns | WARN/BLOCK | -45 Governance |
| SENSITIVE_EXFIL | Sensitive perms + network + no privacy policy | WARN | -40 Privacy |

---

## Table 6: Benchmark Results Summary

### From 36 Extension Scans

| Metric | Value |
|--------|-------|
| Total Extensions Scanned | 36 |
| Average Overall Score | 80.8 |
| Average Security Score | 79.6 |
| Average Privacy Score | 78.9 |
| Average Governance Score | 93.8 |

### Risk Distribution

| Risk Level | Count | Percentage |
|------------|-------|------------|
| None | 3 | 8.3% |
| Low | 15 | 41.7% |
| Medium | 16 | 44.4% |
| High | 2 | 5.6% |

### Decision Distribution

| Decision | Count | Percentage |
|----------|-------|------------|
| ALLOW | 21 | 58.3% |
| NEEDS_REVIEW | 12 | 33.3% |
| BLOCK | 3 | 8.3% |

---

## Table 7: Radar/Spider Chart Data

| Dimension | ExtShield | CRXplorer | ExtAuditor | ExtSec.io | ExtSafe | CRXaminer | CRXcavator |
|-----------|-----------|-----------|------------|-----------|---------|-----------|------------|
| Security | 95 | 70 | 65 | 75 | 80 | 65 | 70 |
| Privacy | 90 | 65 | 70 | 70 | 70 | 50 | 65 |
| Governance | 95 | 40 | 60 | 60 | 40 | 45 | 65 |
| Enterprise | 85 | 50 | 70 | 40 | 40 | 40 | 70 |
| Analysis Depth | 95 | 70 | 55 | 70 | 85 | 70 | 65 |
| Transparency | 90 | 40 | 50 | 95 | 50 | 80 | 60 |

---

## Table 8: Feature Count Comparison

| Category | ExtShield | Best Competitor | Gap |
|----------|-----------|-----------------|-----|
| Security Factors | 7 | 3 (ExtSafe) | +4 |
| Privacy Factors | 4 | 2 (ExtSec.io) | +2 |
| Governance Factors | 3 | 0 | +3 |
| Hard Gates | 5 | 0 | +5 |
| SAST Rules | 47+ | 0 | +47 |
| **Total Factors** | **14** | **~5-7** | **~+7-9** |

---

## Table 9: ExtensionSecurity.io Scoring (For Reference)

| Dimension | Weight | Max Points | Description |
|-----------|--------|------------|-------------|
| Permissions | 30% | 69 | Permission sensitivity |
| Vulnerabilities | 20% | 46 | Known CVEs, outdated libs |
| Domains & URLs | 15% | 34.5 | External domain risk |
| Tracking | 15% | 34.5 | Data collection signals |
| Cross-Origin | 10% | 23 | Cross-origin requests |
| Documentation | 5% | 11.5 | Privacy policy presence |
| Obfuscation | 5% | 11.5 | Code obfuscation |
| **Total** | **100%** | **230** | |

---

## Table 10: ExtSafe Analysis Layers (For Reference)

| Layer | Description |
|-------|-------------|
| Permission Analysis | 82 known permission risk profiles |
| Code Pattern Scanning | 26+ regex patterns |
| AST Analysis | Syntax tree analysis |
| Entropy Detection | Obfuscation via entropy |
| CSP Evaluation | Content Security Policy |
| Manifest Inspection | Manifest.json analysis |
| Vulnerable Library Detection | Known CVE libs |
| IOC Extraction | Indicators of Compromise |
| Combination Risk Detection | 8 combo rules |

---

## Chart Data: Bar Chart - Capability Counts

```
Provider          | Security | Privacy | Governance | Total
------------------|----------|---------|------------|------
ExtensionShield   |    7     |    4    |     3      |  14
ExtSafe           |    5     |    2    |     0      |   7
ExtensionSec.io   |    4     |    2    |     1      |   7
CRXcavator        |    4     |    2    |     1      |   7
CRXplorer         |    3     |    2    |     0      |   5
CRXaminer         |    3     |    1    |     1      |   5
ExtensionAuditor  |    3     |    2    |     1      |   6
```

---

## Chart Data: Pie Chart - ExtensionShield Layer Weights

```
Layer       | Weight | Color Suggestion
------------|--------|------------------
Security    |  50%   | #2563EB (Blue)
Privacy     |  30%   | #7C3AED (Purple)
Governance  |  20%   | #059669 (Green)
```

---

## Chart Data: Risk Distribution Pie

```
Risk Level | Count | Percentage | Color
-----------|-------|------------|-------
None       |   3   |    8.3%    | #10B981 (Green)
Low        |  15   |   41.7%    | #3B82F6 (Blue)
Medium     |  16   |   44.4%    | #F59E0B (Yellow)
High       |   2   |    5.6%    | #EF4444 (Red)
```

---

## Key Stats for Callout Boxes

| Stat | Value | Context |
|------|-------|---------|
| Security Factors | 7 | Most in market |
| Custom SAST Rules | 47+ | Unique to ExtensionShield |
| Hard Gates | 5 | Unique to ExtensionShield |
| Governance Factors | 3 | Unique layer |
| Total Analysis Factors | 14 | 2x competitors |
| Avg Governance Score | 93.8 | Highest layer score |
| Extensions Blocked | 3 (8.3%) | High-risk detection |

---

*Data prepared for PowerPoint import - February 17, 2026*
