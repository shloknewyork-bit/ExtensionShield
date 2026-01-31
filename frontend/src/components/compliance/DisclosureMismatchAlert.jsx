import React, { useState } from "react";
import { Card, CardContent } from "../ui/card";
import { Button } from "../ui/button";
import { Badge } from "../ui/badge";
import { AlertTriangle, ChevronDown, ChevronUp, X } from "lucide-react";
import "./DisclosureMismatchAlert.scss";

const DisclosureMismatchAlert = ({
  disclosureClaims = {},
  signals = [],
  evidenceIndex = {},
}) => {
  const [isExpanded, setIsExpanded] = useState(false);
  const [isDismissed, setIsDismissed] = useState(false);

  // Detect mismatches between disclosure claims and observed signals
  const detectMismatches = () => {
    const mismatches = [];

    // Check for data categories mismatch
    const claimedCategories = disclosureClaims.data_categories || [];
    const observedSignals = signals.filter(
      (s) => s.type === "SENSITIVE_API" || s.type === "DATAFLOW_TRACE"
    );

    if (claimedCategories.length === 0 && observedSignals.length > 0) {
      mismatches.push({
        type: "missing_disclosure",
        message: "Extension collects data but has no disclosure claims",
        severity: "high",
      });
    }

    // Check for endpoint mismatches
    const endpointSignals = signals.filter((s) => s.type === "ENDPOINT_FOUND");
    if (endpointSignals.length > 0 && !disclosureClaims.third_parties?.length) {
      mismatches.push({
        type: "undisclosed_endpoints",
        message: "Extension sends data to endpoints not disclosed in privacy policy",
        severity: "high",
      });
    }

    // Check for data flow without disclosure
    const dataflowSignals = signals.filter((s) => s.type === "DATAFLOW_TRACE");
    if (dataflowSignals.length > 0 && claimedCategories.length === 0) {
      mismatches.push({
        type: "undisclosed_dataflow",
        message: "Data flow detected but no disclosure of data collection",
        severity: "medium",
      });
    }

    return mismatches;
  };

  const mismatches = detectMismatches();

  if (isDismissed || mismatches.length === 0) {
    return null;
  }

  const highSeverityMismatches = mismatches.filter((m) => m.severity === "high");
  const hasHighSeverity = highSeverityMismatches.length > 0;

  return (
    <Card className={`disclosure-mismatch-alert ${hasHighSeverity ? "high-severity" : "medium-severity"}`}>
      <CardContent className="alert-content">
        <div className="alert-header">
          <div className="alert-icon-wrapper">
            <AlertTriangle className="alert-icon" />
          </div>
          <div className="alert-text">
            <div className="alert-title">Disclosure Mismatch Detected</div>
            <div className="alert-subtitle">
              {mismatches.length} {mismatches.length === 1 ? "issue" : "issues"} found between claimed and observed behavior
            </div>
          </div>
          <div className="alert-actions">
            <Button
              variant="ghost"
              size="sm"
              onClick={() => setIsExpanded(!isExpanded)}
              className="expand-btn"
            >
              {isExpanded ? (
                <ChevronUp className="h-4 w-4" />
              ) : (
                <ChevronDown className="h-4 w-4" />
              )}
            </Button>
            <Button
              variant="ghost"
              size="sm"
              onClick={() => setIsDismissed(true)}
              className="dismiss-btn"
            >
              <X className="h-4 w-4" />
            </Button>
          </div>
        </div>

        {isExpanded && (
          <div className="alert-details">
            <div className="mismatches-list">
              {mismatches.map((mismatch, index) => (
                <div
                  key={index}
                  className={`mismatch-item ${mismatch.severity}`}
                >
                  <div className="mismatch-header">
                    <Badge
                      variant={mismatch.severity === "high" ? "destructive" : "secondary"}
                      className="mismatch-severity"
                    >
                      {mismatch.severity.toUpperCase()}
                    </Badge>
                    <span className="mismatch-type">{mismatch.type.replace(/_/g, " ")}</span>
                  </div>
                  <p className="mismatch-message">{mismatch.message}</p>
                </div>
              ))}
            </div>

            {disclosureClaims.data_categories && (
              <div className="disclosure-comparison">
                <div className="comparison-section">
                  <div className="comparison-label">Claimed Data Categories:</div>
                  <div className="comparison-values">
                    {disclosureClaims.data_categories.length > 0 ? (
                      disclosureClaims.data_categories.map((cat, idx) => (
                        <Badge key={idx} variant="outline" className="comparison-badge">
                          {cat}
                        </Badge>
                      ))
                    ) : (
                      <span className="no-data">None disclosed</span>
                    )}
                  </div>
                </div>

                <div className="comparison-section">
                  <div className="comparison-label">Observed Signals:</div>
                  <div className="comparison-values">
                    {signals.length > 0 ? (
                      signals.map((signal, idx) => (
                        <Badge
                          key={idx}
                          variant="outline"
                          className="comparison-badge signal-badge"
                        >
                          {signal.type}
                        </Badge>
                      ))
                    ) : (
                      <span className="no-data">No signals detected</span>
                    )}
                  </div>
                </div>
              </div>
            )}
          </div>
        )}
      </CardContent>
    </Card>
  );
};

export default DisclosureMismatchAlert;









