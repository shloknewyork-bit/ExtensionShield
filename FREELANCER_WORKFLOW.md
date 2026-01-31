# Freelancer Workflow Architecture

Please Read it Carefully, it took me some time to put this project together.

This document outlines how to compartmentalize Project-Atlas for freelancer collaboration, where each person works on isolated components without access to the full codebase.

## 🎯 Core Philosophy
**Contract-Driven Development**: Define clear interfaces (schemas, types) that freelancers code against. They receive input/output contracts + isolated module code, never the full system.

---

## 📦 Logical Work Streams

Based on the architecture, here are 7 independent work streams:

| Stream | Directory | Freelancer Sees | You Keep Private |
|--------|-----------|-----------------|------------------|
| **1. Frontend** | `frontend/` | Full React app | API implementation |
| **2. Analyzers** | `core/analyzers/` | Single analyzer + interface | Other analyzers, workflow |
| **3. API Layer** | `api/` | FastAPI routes | Core logic, LLM |
| **4. LLM Prompts** | `llm/prompts/` | Single prompt YAML | LLM clients, other prompts |
| **5. Governance** | `governance/` | Rules engine only | Signal extraction, context |
| **6. Semgrep Rules** | `config/` | Rule YAML files | Analyzer code |
| **7. UI Components** | `frontend/src/components/` | Single component | App structure |

---

## 🔧 Implementation Approaches

### Approach 1: Separate Git Repositories (Recommended)

Create isolated repos for each work stream with only the necessary code.

```bash
# Directory structure for freelancer repos
freelancer-repos/
├── atlas-frontend/           # React frontend only
├── atlas-analyzer-sast/      # SAST analyzer + interface
├── atlas-analyzer-permissions/
├── atlas-semgrep-rules/      # Just the YAML rules
├── atlas-llm-prompts/        # Just prompt templates
└── atlas-ui-components/      # Individual React components
```

**Setup Script** - Create isolated freelancer repo:

```bash
#!/bin/bash
# scripts/create_freelancer_repo.sh

STREAM=$1  # e.g., "frontend", "analyzer-sast", "semgrep-rules"
OUTPUT_DIR="freelancer-repos/atlas-$STREAM"

mkdir -p "$OUTPUT_DIR"

case $STREAM in
  "frontend")
    cp -r frontend/ "$OUTPUT_DIR/"
    # Remove sensitive service files if needed
    rm -f "$OUTPUT_DIR/src/services/realScanService.js"
    ;;
  "analyzer-sast")
    mkdir -p "$OUTPUT_DIR/src"
    cp src/project_atlas/core/analyzers/sast.py "$OUTPUT_DIR/src/"
    cp src/project_atlas/config/sast_config.json "$OUTPUT_DIR/config/"
    cp src/project_atlas/config/custom_semgrep_rules.yaml "$OUTPUT_DIR/config/"
    # Include interface contract
    cp docs/contracts/analyzer_interface.py "$OUTPUT_DIR/"
    ;;
  "semgrep-rules")
    mkdir -p "$OUTPUT_DIR"
    cp src/project_atlas/config/custom_semgrep_rules.yaml "$OUTPUT_DIR/"
    cp docs/contracts/semgrep_rule_template.yaml "$OUTPUT_DIR/"
    ;;
esac

cd "$OUTPUT_DIR"
git init
git add .
git commit -m "Initial freelancer workspace"
```

---

### Approach 2: Interface Contracts

Create explicit contracts that freelancers code against. They never see the orchestration layer.

**contracts/analyzer_interface.py** - What freelancers receive:

```python
"""
Analyzer Interface Contract
============================
Your analyzer must implement this interface.
"""
from typing import Dict, Any, Optional
from abc import ABC, abstractmethod


class AnalyzerResult:
    """Standard result format all analyzers must return."""
    
    def __init__(
        self,
        analyzer_name: str,
        risk_score: float,  # 0.0 to 1.0
        findings: list[Dict[str, Any]],
        summary: str,
        metadata: Optional[Dict[str, Any]] = None
    ):
        self.analyzer_name = analyzer_name
        self.risk_score = risk_score
        self.findings = findings
        self.summary = summary
        self.metadata = metadata or {}
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "analyzer_name": self.analyzer_name,
            "risk_score": self.risk_score,
            "findings": self.findings,
            "summary": self.summary,
            "metadata": self.metadata
        }


class BaseAnalyzer(ABC):
    """Base class all analyzers must inherit from."""
    
    @abstractmethod
    def analyze(self, extension_dir: str, manifest: Dict[str, Any]) -> AnalyzerResult:
        """
        Analyze a Chrome extension.
        
        Args:
            extension_dir: Path to extracted extension directory
            manifest: Parsed manifest.json as dict
            
        Returns:
            AnalyzerResult with findings
        """
        pass
    
    @property
    @abstractmethod
    def name(self) -> str:
        """Return analyzer name (e.g., 'sast', 'permissions')."""
        pass


# === EXAMPLE IMPLEMENTATION (for reference) ===

class ExampleAnalyzer(BaseAnalyzer):
    """Example implementation - DO NOT COPY, CREATE YOUR OWN."""
    
    @property
    def name(self) -> str:
        return "example"
    
    def analyze(self, extension_dir: str, manifest: Dict[str, Any]) -> AnalyzerResult:
        findings = []
        
        # Your analysis logic here
        # ...
        
        return AnalyzerResult(
            analyzer_name=self.name,
            risk_score=0.3,
            findings=findings,
            summary="Found X issues"
        )
```

**contracts/frontend_api_spec.yaml** - API contract for frontend freelancer:

```yaml
# OpenAPI spec - what the frontend developer receives
openapi: 3.0.0
info:
  title: Project Atlas API
  version: 1.0.0
  description: API contract for Chrome Extension Security Scanner

paths:
  /scan:
    post:
      summary: Start extension scan
      requestBody:
        content:
          application/json:
            schema:
              type: object
              properties:
                url:
                  type: string
                  example: "https://chromewebstore.google.com/detail/..."
      responses:
        "200":
          content:
            application/json:
              schema:
                $ref: "#/components/schemas/ScanResponse"

  /scan/{scan_id}/status:
    get:
      summary: Get scan status
      parameters:
        - name: scan_id
          in: path
          required: true
          schema:
            type: string
      responses:
        "200":
          content:
            application/json:
              schema:
                $ref: "#/components/schemas/StatusResponse"

components:
  schemas:
    ScanResponse:
      type: object
      properties:
        scan_id:
          type: string
        status:
          type: string
          enum: [pending, running, completed, failed]
    
    StatusResponse:
      type: object
      properties:
        status:
          type: string
        progress:
          type: number
        current_step:
          type: string
        results:
          $ref: "#/components/schemas/AnalysisResults"
    
    AnalysisResults:
      type: object
      properties:
        overall_risk_score:
          type: number
        risk_level:
          type: string
          enum: [low, medium, high, critical]
        manifest:
          type: object
        permissions_analysis:
          type: object
        sast_analysis:
          type: object
        webstore_analysis:
          type: object
        executive_summary:
          type: object
```

---

### Approach 3: GitHub Repository Templates

Create template repos for each work stream:

```bash
# For each work stream, create a GitHub template repository

# 1. atlas-analyzer-template
#    - Contains: analyzer_interface.py, sample analyzer, test fixtures
#    - Freelancer forks this, implements their analyzer

# 2. atlas-semgrep-rules-template  
#    - Contains: rule template, test extension samples
#    - Freelancer adds new rules following template

# 3. atlas-ui-component-template
#    - Contains: component boilerplate, design system tokens, storybook
#    - Freelancer builds component in isolation
```

---

## 📋 Freelancer Assignment Templates

### Template: New Analyzer Assignment

```markdown
# Assignment: Build [Analyzer Name] Analyzer

## Context
You're building a security analyzer for Chrome extensions. Your analyzer will be 
integrated into a larger pipeline, but you only need to focus on this specific module.

## Deliverables
1. `my_analyzer.py` - Implementation inheriting from `BaseAnalyzer`
2. `tests/test_my_analyzer.py` - Unit tests
3. `README.md` - Usage documentation

## Interface Contract
Your analyzer must:
- Inherit from `BaseAnalyzer` (provided in `analyzer_interface.py`)
- Implement `analyze(extension_dir, manifest) -> AnalyzerResult`
- Return findings in the specified format

## Input You'll Receive
- `extension_dir`: Path to extracted extension (contains JS files, manifest.json, etc.)
- `manifest`: Dict with parsed manifest.json

## Output Format (AnalyzerResult)
```python
{
    "analyzer_name": "your_analyzer",
    "risk_score": 0.0 to 1.0,
    "findings": [
        {
            "type": "issue_type",
            "severity": "high|medium|low",
            "description": "What was found",
            "file": "path/to/file.js",
            "line": 42,
            "evidence": "code snippet"
        }
    ],
    "summary": "Brief summary of findings"
}
```

## Test Fixtures Provided
- `fixtures/benign_extension/` - Clean extension for baseline
- `fixtures/malicious_extension/` - Known bad extension to detect

## Evaluation Criteria
- Detects issues in malicious fixture
- No false positives on benign fixture
- Code quality and documentation
```

---

### Template: Frontend Component Assignment

```markdown
# Assignment: Build [Component Name] Component

## Context
You're building a React component for a security scanning dashboard. 
The component will be integrated into a larger app.

## Design System
- Uses Tailwind CSS + shadcn/ui
- Color tokens in `_theme-tokens.scss`
- Animation patterns in `_animations.scss`

## Props Interface
```typescript
interface ComponentProps {
  data: AnalysisResult;
  onAction?: (action: string) => void;
  loading?: boolean;
}
```

## API Data Format (mock provided)
```json
{
  "risk_score": 0.72,
  "risk_level": "high",
  "findings": [...],
  "recommendations": [...]
}
```

## Deliverables
1. `MyComponent.jsx` - React component
2. `MyComponent.scss` - Styles (SCSS)
3. `MyComponent.stories.jsx` - Storybook stories (optional)

## Mock Data
Use `mockData.json` to develop against. The real API follows this exact format.
```

---

### Template: Semgrep Rules Assignment

```markdown
# Assignment: Create Semgrep Rules for [Category]

## Context
You're writing custom Semgrep rules to detect malicious patterns in Chrome extensions.

## Deliverables
1. Add rules to `custom_rules.yaml`
2. Create test cases in `test_cases/`

## Rule Template
```yaml
rules:
  - id: your-rule-id
    message: "Description of what this detects"
    severity: ERROR  # ERROR, WARNING, INFO
    languages: [javascript, typescript]
    metadata:
      category: security
      cwe: "CWE-XXX"
      mitre_attack: "T1XXX"
    patterns:
      - pattern: |
          $FUNC(...)
```

## Test Case Format
For each rule, provide:
- `positive_test.js` - Code that SHOULD trigger the rule
- `negative_test.js` - Code that should NOT trigger

## Run Tests
```bash
semgrep --config custom_rules.yaml test_cases/
```
```

---

## 🔒 Security Considerations

### What Freelancers Should NEVER Receive:

1. **Workflow orchestration** (`workflow/graph.py`, `workflow/nodes.py`)
2. **LLM client implementations** (`llm/clients/`)
3. **API keys / credentials** (`.env` files)
4. **Full state management** (`workflow/state.py` - give them input/output only)
5. **Other analyzers' code** (they only see their assigned module)
6. **Database/persistence layer** (`api/database.py`)

### Sanitize Before Sharing:

```bash
# Script to sanitize code before sharing
#!/bin/bash

# Remove all .env files
find . -name ".env*" -delete

# Remove git history
rm -rf .git

# Remove sensitive configs
rm -f src/project_atlas/llm/clients/*.py
rm -f src/project_atlas/api/database.py

# Remove workflow orchestration
rm -f src/project_atlas/workflow/graph.py
rm -f src/project_atlas/workflow/nodes.py
```

---

## 📁 Recommended Directory Structure for Freelancer Repos

```
freelancer-analyzer-repo/
├── README.md                 # Assignment instructions
├── INTERFACE.md              # Contract documentation
├── src/
│   └── my_analyzer.py        # Their implementation
├── contracts/
│   └── analyzer_interface.py # Base class they inherit from
├── fixtures/
│   ├── benign_extension/     # Test extension (safe)
│   └── malicious_extension/  # Test extension (malicious)
├── tests/
│   └── test_my_analyzer.py   # Their tests
└── requirements.txt          # Minimal dependencies
```

---

## 🔄 Integration Workflow

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│   Freelancer    │     │   Your Review   │     │   Integration   │
│   Implements    │────▶│   & Testing     │────▶│   Into Main     │
│   Module        │     │                 │     │   Codebase      │
└─────────────────┘     └─────────────────┘     └─────────────────┘
        │                       │                       │
        ▼                       ▼                       ▼
  Isolated Repo           PR Review              Workflow wiring
  with contracts          Unit tests             State integration
                          Contract validation
```

### Integration Checklist:

- [ ] Freelancer code follows interface contract
- [ ] All tests pass
- [ ] No hardcoded paths or credentials
- [ ] Code style matches project (Black, 100 char lines)
- [ ] Documentation complete
- [ ] Wire into `workflow/nodes.py` 
- [ ] Update `workflow/graph.py` if new node
- [ ] End-to-end test in full pipeline

---

## 📝 Quick Start Commands

```bash
# Create a new freelancer repo for an analyzer
./scripts/create_freelancer_repo.sh analyzer-sast

# Create a new freelancer repo for frontend
./scripts/create_freelancer_repo.sh frontend

# Create a new freelancer repo for Semgrep rules
./scripts/create_freelancer_repo.sh semgrep-rules

# Validate freelancer submission against contract
python scripts/validate_submission.py --type analyzer --path ./submission/
```

---

## 🎯 Example Work Stream Breakdown

| Freelancer | Assigned Work | Repo They Get | Contract |
|------------|---------------|---------------|----------|
| Dev A | SAST Analyzer improvements | `atlas-analyzer-sast` | `BaseAnalyzer` |
| Dev B | New entropy analyzer | `atlas-analyzer-template` | `BaseAnalyzer` |
| Dev C | Frontend dashboard | `atlas-frontend` | OpenAPI spec |
| Dev D | Compliance matrix UI | `atlas-ui-components` | Props interface |
| Dev E | Banking fraud Semgrep rules | `atlas-semgrep-rules` | Rule template |
| Dev F | LLM prompts for analysis | `atlas-llm-prompts` | Prompt template |

---

## Next Steps

1. Create `contracts/` directory with interface definitions
2. Set up GitHub template repositories
3. Write assignment templates for each work stream
4. Create `scripts/create_freelancer_repo.sh`
5. Set up integration testing pipeline

