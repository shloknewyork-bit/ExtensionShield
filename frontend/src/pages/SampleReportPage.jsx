import React, { useState } from "react";
import { useNavigate } from "react-router-dom";
import { Button } from "../components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
} from "../components/ui/dialog";
import { Badge } from "../components/ui/badge";
import "./SampleReportPage.scss";

// Mock data
const mockReportData = {
  extension_name: "Sample Extension Pro",
  scan_id: "scan_20241215_abc123xyz",
  timestamp: new Date().toISOString(),
  overall_verdict: "NEEDS_REVIEW",
  summary: {
    fail_count: 2,
    needs_review_count: 3,
    pass_count: 8,
  },
  rulepacks: ["CWS_LIMITED_USE", "DPDP_RISK_INDICATORS"],
  findings: [
    {
      id: "finding_001",
      verdict: "FAIL",
      rule_id: "CWS_LIMITED_USE_001",
      title: "Excessive Permission Request",
      confidence: "HIGH",
      evidence_count: 2,
      explanation: "Extension requests '<all_urls>' permission without clear justification in manifest description. This violates Chrome Web Store policy 3.1 which requires extensions to request only the minimum permissions necessary for functionality.",
      evidence: [
        {
          file_path: "manifest.json",
          line_range: "12-15",
          snippet: '"permissions": ["storage", "tabs", "<all_urls>"]',
        },
        {
          file_path: "background.js",
          line_range: "45-52",
          snippet: "chrome.tabs.query({ url: ['<all_urls>'] }, (tabs) => { ... });",
        },
      ],
      citations: [
        {
          citation_id: "CWS_3.1",
          title: "Chrome Web Store Policy 3.1 - Permission Justification",
          source_link: "#",
        },
        {
          citation_id: "CWS_3.2",
          title: "Chrome Web Store Policy 3.2 - Limited Use Requirements",
          source_link: "#",
        },
      ],
    },
    {
      id: "finding_002",
      verdict: "NEEDS_REVIEW",
      rule_id: "DPDP_RISK_INDICATORS_005",
      title: "Data Collection Without Disclosure",
      confidence: "MEDIUM",
      evidence_count: 3,
      explanation: "Extension collects user data (browsing history, form inputs) but privacy policy link in manifest is missing or invalid. DPDP v0 requires explicit disclosure of data collection practices.",
      evidence: [
        {
          file_path: "background.js",
          line_range: "78-85",
          snippet: "chrome.history.search({ text: '', maxResults: 100 }, (results) => { ... });",
        },
        {
          file_path: "content.js",
          line_range: "23-30",
          snippet: "document.addEventListener('input', (e) => { collectFormData(e.target.value); });",
        },
        {
          file_path: "manifest.json",
          line_range: "8-8",
          snippet: '"privacy_policy": ""',
        },
      ],
      citations: [
        {
          citation_id: "DPDP_4.2",
          title: "DPDP v0 Section 4.2 - Data Collection Disclosure",
          source_link: "#",
        },
      ],
    },
    {
      id: "finding_003",
      verdict: "NEEDS_REVIEW",
      rule_id: "CWS_LIMITED_USE_003",
      title: "Third-Party Data Sharing",
      confidence: "MEDIUM",
      evidence_count: 1,
      explanation: "Extension sends collected data to external domain (analytics.example.com) without user consent mechanism. This may violate data sharing requirements if not properly disclosed.",
      evidence: [
        {
          file_path: "analytics.js",
          line_range: "12-18",
          snippet: "fetch('https://analytics.example.com/track', { method: 'POST', body: JSON.stringify(userData) });",
        },
      ],
      citations: [
        {
          citation_id: "CWS_3.5",
          title: "Chrome Web Store Policy 3.5 - Third-Party Data Sharing",
          source_link: "#",
        },
        {
          citation_id: "DPDP_5.1",
          title: "DPDP v0 Section 5.1 - Data Sharing Consent",
          source_link: "#",
        },
      ],
    },
    {
      id: "finding_004",
      verdict: "FAIL",
      rule_id: "DPDP_RISK_INDICATORS_002",
      title: "Sensitive Data Storage",
      confidence: "HIGH",
      evidence_count: 2,
      explanation: "Extension stores sensitive user credentials in chrome.storage.local without encryption. This violates security best practices and may violate data protection requirements.",
      evidence: [
        {
          file_path: "storage.js",
          line_range: "34-40",
          snippet: "chrome.storage.local.set({ password: userPassword, apiKey: apiKey });",
        },
        {
          file_path: "storage.js",
          line_range: "45-50",
          snippet: "const stored = await chrome.storage.local.get(['password', 'apiKey']);",
        },
      ],
      citations: [
        {
          citation_id: "DPDP_6.3",
          title: "DPDP v0 Section 6.3 - Data Security Requirements",
          source_link: "#",
        },
      ],
    },
    {
      id: "finding_005",
      verdict: "NEEDS_REVIEW",
      rule_id: "CWS_LIMITED_USE_007",
      title: "Obfuscated Code Detected",
      confidence: "LOW",
      evidence_count: 1,
      explanation: "Code appears to be obfuscated or minified beyond standard practices. Chrome Web Store requires review of obfuscated code to ensure compliance.",
      evidence: [
        {
          file_path: "vendor.min.js",
          line_range: "1-1",
          snippet: "var _0x1a2b=['\x48\x65\x6c\x6c\x6f','\x57\x6f\x72\x6c\x64'];...",
        },
      ],
      citations: [
        {
          citation_id: "CWS_4.1",
          title: "Chrome Web Store Policy 4.1 - Code Review Requirements",
          source_link: "#",
        },
      ],
    },
  ],
};

const SampleReportPage = () => {
  const navigate = useNavigate();
  const [selectedFinding, setSelectedFinding] = useState(null);
  const [isDialogOpen, setIsDialogOpen] = useState(false);

  const formatTimestamp = (timestamp) => {
    const date = new Date(timestamp);
    return date.toLocaleString("en-US", {
      year: "numeric",
      month: "long",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit",
    });
  };

  const handleFindingClick = (finding) => {
    setSelectedFinding(finding);
    setIsDialogOpen(true);
  };

  const getVerdictBadgeVariant = (verdict) => {
    switch (verdict) {
      case "FAIL":
        return "destructive";
      case "NEEDS_REVIEW":
        return "secondary";
      case "PASS":
        return "default";
      default:
        return "outline";
    }
  };

  const getConfidenceColor = (confidence) => {
    switch (confidence) {
      case "HIGH":
        return "var(--color-destructive)";
      case "MEDIUM":
        return "var(--color-warning)";
      case "LOW":
        return "var(--color-foreground-muted)";
      default:
        return "var(--color-foreground-muted)";
    }
  };

  return (
    <div className="sample-report-page">
      <div className="sample-report-container">
        <Button
          variant="ghost"
          onClick={() => navigate("/")}
          className="back-button"
        >
          ← Back to Scanner
        </Button>

        <div className="sample-report-content">
          {/* Header */}
          <div className="report-header">
            <div className="report-header-main">
              <h1 className="report-title">{mockReportData.extension_name}</h1>
              <div className="report-meta">
                <span className="report-scan-id">Scan ID: {mockReportData.scan_id}</span>
                <span className="report-separator">•</span>
                <span className="report-timestamp">{formatTimestamp(mockReportData.timestamp)}</span>
              </div>
            </div>
            <div className="report-header-actions">
              <Button
                variant="outline"
                disabled
                className="export-btn"
                title="Coming in Phase 2"
              >
                Download JSON
              </Button>
              <Button
                variant="outline"
                disabled
                className="export-btn"
                title="Coming in Phase 2"
              >
                Download PDF
              </Button>
            </div>
          </div>

          {/* Summary Cards */}
          <div className="summary-cards">
            <div className="summary-card overall-verdict">
              <div className="summary-card-label">Overall Verdict</div>
              <div className="summary-card-value">
                <Badge variant={getVerdictBadgeVariant(mockReportData.overall_verdict)} className="verdict-badge-large">
                  {mockReportData.overall_verdict}
                </Badge>
              </div>
            </div>
            <div className="summary-card">
              <div className="summary-card-label">Fail</div>
              <div className="summary-card-value fail-count">{mockReportData.summary.fail_count}</div>
            </div>
            <div className="summary-card">
              <div className="summary-card-label">Needs Review</div>
              <div className="summary-card-value needs-review-count">{mockReportData.summary.needs_review_count}</div>
            </div>
            <div className="summary-card">
              <div className="summary-card-label">Pass</div>
              <div className="summary-card-value pass-count">{mockReportData.summary.pass_count}</div>
            </div>
            <div className="summary-card rulepacks">
              <div className="summary-card-label">Rulepacks Enabled</div>
              <div className="summary-card-value rulepacks-list">
                {mockReportData.rulepacks.map((pack, idx) => (
                  <Badge key={idx} variant="outline" className="rulepack-badge">
                    {pack}
                  </Badge>
                ))}
              </div>
            </div>
          </div>

          {/* Findings Table */}
          <div className="findings-section">
            <h2 className="section-title">Findings</h2>
            <div className="findings-table-container">
              <table className="findings-table">
                <thead>
                  <tr>
                    <th>Verdict</th>
                    <th>Rule ID</th>
                    <th>Title</th>
                    <th>Confidence</th>
                    <th>Evidence</th>
                  </tr>
                </thead>
                <tbody>
                  {mockReportData.findings.map((finding) => (
                    <tr
                      key={finding.id}
                      className="finding-row"
                      onClick={() => handleFindingClick(finding)}
                    >
                      <td>
                        <Badge variant={getVerdictBadgeVariant(finding.verdict)}>
                          {finding.verdict}
                        </Badge>
                      </td>
                      <td className="rule-id-cell">{finding.rule_id}</td>
                      <td className="title-cell">{finding.title}</td>
                      <td>
                        <span
                          className="confidence-badge"
                          style={{ color: getConfidenceColor(finding.confidence) }}
                        >
                          {finding.confidence}
                        </span>
                      </td>
                      <td className="evidence-count-cell">
                        {finding.evidence_count} {finding.evidence_count === 1 ? "item" : "items"}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          {/* Footer */}
          <div className="report-footer">
            <p className="footer-disclaimer">
              This is a sample compliance report generated using deterministic rule evaluation and static code analysis. 
              Reports are evidence-based and do not constitute legal advice or compliance guarantees.
            </p>
            <Button onClick={() => navigate("/")} className="start-scan-btn">
              Start Your Scan
            </Button>
          </div>
        </div>
      </div>

      {/* Finding Details Dialog */}
      <Dialog open={isDialogOpen} onOpenChange={setIsDialogOpen}>
        <DialogContent className="finding-dialog">
          <DialogHeader>
            <DialogTitle className="finding-dialog-title">
              {selectedFinding?.title}
            </DialogTitle>
            <DialogDescription className="finding-dialog-meta">
              <Badge variant={getVerdictBadgeVariant(selectedFinding?.verdict)}>
                {selectedFinding?.verdict}
              </Badge>
              <span className="finding-rule-id">{selectedFinding?.rule_id}</span>
            </DialogDescription>
          </DialogHeader>

          {selectedFinding && (
            <div className="finding-details">
              {/* Explanation */}
              <div className="finding-section">
                <h3 className="finding-section-title">Explanation</h3>
                <p className="finding-explanation">{selectedFinding.explanation}</p>
              </div>

              {/* Evidence List */}
              <div className="finding-section">
                <h3 className="finding-section-title">
                  Evidence ({selectedFinding.evidence.length} {selectedFinding.evidence.length === 1 ? "item" : "items"})
                </h3>
                <div className="evidence-list">
                  {selectedFinding.evidence.map((ev, idx) => (
                    <div key={idx} className="evidence-item">
                      <div className="evidence-header">
                        <span className="evidence-file-path">{ev.file_path}</span>
                        <span className="evidence-line-range">Lines {ev.line_range}</span>
                      </div>
                      <div className="evidence-snippet">
                        <code>{ev.snippet}</code>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* Citations List */}
              <div className="finding-section">
                <h3 className="finding-section-title">
                  Citations ({selectedFinding.citations.length} {selectedFinding.citations.length === 1 ? "reference" : "references"})
                </h3>
                <div className="citations-list">
                  {selectedFinding.citations.map((citation, idx) => (
                    <div key={idx} className="citation-item">
                      <div className="citation-header">
                        <span className="citation-id">{citation.citation_id}</span>
                        <span className="citation-title">{citation.title}</span>
                      </div>
                      <a
                        href={citation.source_link}
                        className="citation-link"
                        onClick={(e) => {
                          e.preventDefault();
                          // Placeholder - would link to actual policy document
                        }}
                      >
                        View Policy Document →
                      </a>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}
        </DialogContent>
      </Dialog>
    </div>
  );
};

export default SampleReportPage;
