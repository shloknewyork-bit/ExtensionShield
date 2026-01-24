import React, { useState } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "../ui/card";
import { Button } from "../ui/button";
import { Badge } from "../ui/badge";
import { ChevronDown, ChevronUp, Eye } from "lucide-react";
import CitationBadge from "./CitationBadge";
import "./ComplianceMatrixCard.scss";

const ComplianceMatrixCard = ({ ruleResults = [], evidenceIndex = {}, citations = {}, onViewEvidence }) => {
  const [expandedRules, setExpandedRules] = useState({});
  const [expandedRulepacks, setExpandedRulepacks] = useState({});

  // Group rules by rulepack
  const groupedRules = ruleResults.reduce((acc, rule) => {
    const rulepack = rule.rulepack || "UNKNOWN";
    if (!acc[rulepack]) {
      acc[rulepack] = [];
    }
    acc[rulepack].push(rule);
    return acc;
  }, {});

  const toggleRule = (ruleId) => {
    setExpandedRules((prev) => ({
      ...prev,
      [ruleId]: !prev[ruleId],
    }));
  };

  const toggleRulepack = (rulepack) => {
    setExpandedRulepacks((prev) => ({
      ...prev,
      [rulepack]: !prev[rulepack],
    }));
  };

  const getVerdictColor = (verdict) => {
    switch (verdict) {
      case "PASS":
        return "verdict-pass";
      case "FAIL":
        return "verdict-fail";
      case "NEEDS_REVIEW":
        return "verdict-review";
      default:
        return "verdict-unknown";
    }
  };

  const getVerdictBadgeVariant = (verdict) => {
    switch (verdict) {
      case "PASS":
        return "default";
      case "FAIL":
        return "destructive";
      case "NEEDS_REVIEW":
        return "secondary";
      default:
        return "outline";
    }
  };

  const getConfidenceBadge = (confidence) => {
    if (confidence >= 0.95) return { label: "High", className: "confidence-high" };
    if (confidence >= 0.80) return { label: "Medium", className: "confidence-medium" };
    return { label: "Low", className: "confidence-low" };
  };

  if (ruleResults.length === 0) {
    return (
      <Card className="compliance-matrix-card">
        <CardContent className="p-8 text-center text-muted-foreground">
          <p>No compliance data available. Run a scan to see compliance results.</p>
        </CardContent>
      </Card>
    );
  }

  return (
    <div className="compliance-matrix-container space-y-4">
      {Object.entries(groupedRules).map(([rulepack, rules]) => (
        <Card key={rulepack} className="compliance-matrix-card rulepack-card">
          <CardHeader className="rulepack-header">
            <div className="flex items-center justify-between">
              <CardTitle className="rulepack-title">
                <span className="rulepack-name">{rulepack}</span>
                <Badge variant="outline" className="ml-2">
                  {rules.length} {rules.length === 1 ? "rule" : "rules"}
                </Badge>
              </CardTitle>
              <Button
                variant="ghost"
                size="sm"
                onClick={() => toggleRulepack(rulepack)}
                className="expand-toggle"
              >
                {expandedRulepacks[rulepack] ? (
                  <ChevronUp className="h-4 w-4" />
                ) : (
                  <ChevronDown className="h-4 w-4" />
                )}
              </Button>
            </div>
          </CardHeader>

          {!expandedRulepacks[rulepack] && (
            <CardContent>
              <div className="rulepack-summary">
                <div className="summary-stats">
                  <div className="stat-item">
                    <span className="stat-label">Pass:</span>
                    <span className="stat-value pass">
                      {rules.filter((r) => r.verdict === "PASS").length}
                    </span>
                  </div>
                  <div className="stat-item">
                    <span className="stat-label">Fail:</span>
                    <span className="stat-value fail">
                      {rules.filter((r) => r.verdict === "FAIL").length}
                    </span>
                  </div>
                  <div className="stat-item">
                    <span className="stat-label">Review:</span>
                    <span className="stat-value review">
                      {rules.filter((r) => r.verdict === "NEEDS_REVIEW").length}
                    </span>
                  </div>
                </div>
              </div>
            </CardContent>
          )}

          {expandedRulepacks[rulepack] && (
            <CardContent>
              <div className="rules-list space-y-3">
                {rules.map((rule) => (
                  <div
                    key={rule.rule_id}
                    className={`rule-item ${getVerdictColor(rule.verdict)}`}
                  >
                    <div className="rule-header">
                      <div className="rule-info">
                        <div className="rule-id-row">
                          <span className="rule-id">{rule.rule_id}</span>
                          <Badge
                            variant={getVerdictBadgeVariant(rule.verdict)}
                            className="verdict-badge"
                          >
                            {rule.verdict}
                          </Badge>
                          <Badge
                            variant="outline"
                            className={`confidence-badge ${getConfidenceBadge(rule.confidence).className}`}
                          >
                            {getConfidenceBadge(rule.confidence).label} ({Math.round(rule.confidence * 100)}%)
                          </Badge>
                        </div>
                        {rule.explanation && (
                          <p className="rule-explanation">{rule.explanation}</p>
                        )}
                      </div>
                      <div className="rule-actions">
                        {rule.evidence_refs && rule.evidence_refs.length > 0 && (
                          <Button
                            variant="outline"
                            size="sm"
                            onClick={() => onViewEvidence(rule.evidence_refs)}
                            className="view-evidence-btn"
                          >
                            <Eye className="h-4 w-4 mr-1" />
                            View Evidence ({rule.evidence_refs.length})
                          </Button>
                        )}
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => toggleRule(rule.rule_id)}
                          className="expand-rule-btn"
                        >
                          {expandedRules[rule.rule_id] ? (
                            <ChevronUp className="h-4 w-4" />
                          ) : (
                            <ChevronDown className="h-4 w-4" />
                          )}
                        </Button>
                      </div>
                    </div>

                    {expandedRules[rule.rule_id] && (
                      <div className="rule-details">
                        {rule.citations && rule.citations.length > 0 && (
                          <div className="rule-citations">
                            <span className="citations-label">Citations:</span>
                            <div className="citations-list">
                              {rule.citations.map((citationId, idx) => (
                                <CitationBadge
                                  key={idx}
                                  citationId={citationId}
                                  citation={citations[citationId]}
                                />
                              ))}
                            </div>
                          </div>
                        )}
                        {rule.evidence_refs && rule.evidence_refs.length > 0 && (
                          <div className="rule-evidence-refs">
                            <span className="evidence-label">Evidence References:</span>
                            <div className="evidence-refs-list">
                              {rule.evidence_refs.map((ref, idx) => (
                                <code key={idx} className="evidence-ref">
                                  {ref}
                                </code>
                              ))}
                            </div>
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </CardContent>
          )}
        </Card>
      ))}
    </div>
  );
};

export default ComplianceMatrixCard;

