import React from "react";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
} from "../ui/dialog";
import { Button } from "../ui/button";
import { Badge } from "../ui/badge";
import { Copy, ExternalLink, FileText, Calendar, Hash } from "lucide-react";
import "./EvidenceModal.scss";

const EvidenceModal = ({ evidenceRefs = [], evidenceIndex = {}, isOpen, onClose }) => {
  const copyToClipboard = (text) => {
    navigator.clipboard.writeText(text);
    // You could add a toast notification here
  };

  const getEvidenceTypeIcon = (type) => {
    switch (type) {
      case "code":
        return "💻";
      case "manifest":
        return "📄";
      case "network":
        return "🌐";
      case "metadata":
        return "📊";
      case "policy_text":
        return "📋";
      default:
        return "📝";
    }
  };

  const getEvidenceTypeColor = (type) => {
    switch (type) {
      case "code":
        return "type-code";
      case "manifest":
        return "type-manifest";
      case "network":
        return "type-network";
      case "metadata":
        return "type-metadata";
      case "policy_text":
        return "type-policy";
      default:
        return "type-default";
    }
  };

  if (!isOpen || evidenceRefs.length === 0) {
    return null;
  }

  const evidenceEntries = evidenceRefs
    .map((ref) => evidenceIndex[ref])
    .filter((entry) => entry != null);

  return (
    <Dialog open={isOpen} onOpenChange={onClose}>
      <DialogContent className="evidence-modal-content">
        <DialogHeader>
          <DialogTitle className="evidence-modal-title">
            Evidence Details
            <Badge variant="outline" className="ml-2">
              {evidenceEntries.length} {evidenceEntries.length === 1 ? "item" : "items"}
            </Badge>
          </DialogTitle>
          <DialogDescription className="evidence-modal-description">
            View code snippets, manifest excerpts, and network traces that support the compliance findings.
          </DialogDescription>
        </DialogHeader>

        <div className="evidence-list space-y-4">
          {evidenceEntries.map((evidence, index) => (
            <div
              key={evidence.evidence_id || index}
              className={`evidence-item ${getEvidenceTypeColor(evidence.type)}`}
            >
              <div className="evidence-header">
                <div className="evidence-type-badge">
                  <span className="evidence-type-icon">
                    {getEvidenceTypeIcon(evidence.type)}
                  </span>
                  <span className="evidence-type-label">{evidence.type?.toUpperCase() || "UNKNOWN"}</span>
                </div>
                <div className="evidence-id">
                  <Hash className="h-3 w-3" />
                  <code>{evidence.evidence_id}</code>
                </div>
              </div>

              {evidence.artifact && (
                <div className="evidence-artifact">
                  <div className="artifact-row">
                    <FileText className="h-4 w-4" />
                    <span className="artifact-label">File:</span>
                    <code className="artifact-value">{evidence.artifact.file_path}</code>
                  </div>
                  {evidence.artifact.line_start && evidence.artifact.line_end && (
                    <div className="artifact-row">
                      <span className="artifact-label">Lines:</span>
                      <code className="artifact-value">
                        {evidence.artifact.line_start} - {evidence.artifact.line_end}
                      </code>
                    </div>
                  )}
                  {evidence.artifact.sha256 && (
                    <div className="artifact-row">
                      <Hash className="h-4 w-4" />
                      <span className="artifact-label">SHA256:</span>
                      <code className="artifact-value sha256">
                        {evidence.artifact.sha256.substring(0, 16)}...
                      </code>
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => copyToClipboard(evidence.artifact.sha256)}
                        className="copy-btn"
                      >
                        <Copy className="h-3 w-3" />
                      </Button>
                    </div>
                  )}
                </div>
              )}

              {evidence.snippet && (
                <div className="evidence-snippet">
                  <div className="snippet-header">
                    <span className="snippet-label">Code Snippet</span>
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => copyToClipboard(evidence.snippet)}
                      className="copy-snippet-btn"
                    >
                      <Copy className="h-3 w-3 mr-1" />
                      Copy
                    </Button>
                  </div>
                  <pre className="snippet-content">
                    <code>{evidence.snippet}</code>
                  </pre>
                </div>
              )}

              {evidence.provenance && (
                <div className="evidence-provenance">
                  <div className="provenance-row">
                    <Calendar className="h-4 w-4" />
                    <span className="provenance-label">Collected:</span>
                    <span className="provenance-value">
                      {new Date(evidence.provenance.collected_at).toLocaleString()}
                    </span>
                  </div>
                  <div className="provenance-row">
                    <span className="provenance-label">Source:</span>
                    <Badge variant="outline" className="provenance-badge">
                      {evidence.provenance.source?.toUpperCase() || "UNKNOWN"}
                    </Badge>
                  </div>
                  {evidence.provenance.artifact_hash && (
                    <div className="provenance-row">
                      <Hash className="h-4 w-4" />
                      <span className="provenance-label">Artifact Hash:</span>
                      <code className="provenance-value hash">
                        {evidence.provenance.artifact_hash.substring(0, 16)}...
                      </code>
                    </div>
                  )}
                </div>
              )}

              {evidence.redactions && evidence.redactions.length > 0 && (
                <div className="evidence-redactions">
                  <Badge variant="outline" className="redaction-badge">
                    Redacted: {evidence.redactions.join(", ")}
                  </Badge>
                </div>
              )}
            </div>
          ))}
        </div>

        <div className="evidence-modal-footer">
          <Button variant="outline" onClick={onClose}>
            Close
          </Button>
        </div>
      </DialogContent>
    </Dialog>
  );
};

export default EvidenceModal;









