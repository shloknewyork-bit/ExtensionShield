import React, { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { Button } from "../../components/ui/button";
import { Badge } from "../../components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "../../components/ui/card";
import databaseService from "../../services/databaseService";
import "./ReportsPage.scss";

const ReportsPage = () => {
  const navigate = useNavigate();
  const [reports, setReports] = useState([]);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    loadReports();
  }, []);

  const loadReports = async () => {
    try {
      setIsLoading(true);
      const history = await databaseService.getScanHistory(50);
      setReports(history);
    } catch (error) {
      console.error("Failed to load reports:", error);
    } finally {
      setIsLoading(false);
    }
  };

  // Map risk level to governance verdict
  const getGovernanceVerdict = (report) => {
    const riskLevel = (report.risk_level || report.riskLevel || "").toUpperCase();
    const score = report.security_score || report.securityScore || 0;
    
    if (riskLevel === "HIGH" || riskLevel === "CRITICAL" || score < 30) {
      return "BLOCK";
    } else if (riskLevel === "MEDIUM" || score < 70) {
      return "NEEDS_REVIEW";
    }
    return "ALLOW";
  };

  const getVerdictStyle = (verdict) => {
    switch (verdict) {
      case "ALLOW":
        return { variant: "success", icon: "✓", className: "verdict-allow" };
      case "BLOCK":
        return { variant: "destructive", icon: "✕", className: "verdict-block" };
      case "NEEDS_REVIEW":
        return { variant: "warning", icon: "!", className: "verdict-review" };
      default:
        return { variant: "secondary", icon: "?", className: "verdict-unknown" };
    }
  };

  const handleViewReport = (extensionId) => {
    navigate(`/reports/${extensionId}`);
  };

  const handleDownloadPDF = async (extensionId) => {
    const baseURL = import.meta.env.VITE_API_URL || "";
    window.open(`${baseURL}/api/scan/report/${extensionId}`, '_blank');
  };

  // Stats summary
  const stats = {
    total: reports.length,
    allowed: reports.filter(r => getGovernanceVerdict(r) === "ALLOW").length,
    blocked: reports.filter(r => getGovernanceVerdict(r) === "BLOCK").length,
    review: reports.filter(r => getGovernanceVerdict(r) === "NEEDS_REVIEW").length,
  };

  return (
    <div className="reports-page">
      {/* Background Effects */}
      <div className="reports-bg-effects">
        <div className="reports-bg-gradient reports-gradient-1" />
        <div className="reports-bg-gradient reports-gradient-2" />
      </div>

      {/* Content */}
      <div className="reports-content">
        {/* Header */}
        <header className="reports-header">
          <div className="reports-header-content">
            <h1 className="reports-title">
              <span className="title-icon">📋</span>
              Security Reports
            </h1>
            <p className="reports-subtitle">Extension security verdicts with evidence citations</p>
          </div>
          <Button onClick={() => navigate("/scanner")} className="scan-btn">
            + New Scan
          </Button>
        </header>

        {/* Stats Cards */}
        {reports.length > 0 && (
          <div className="stats-grid">
            <div className="stat-card stat-total">
              <div className="stat-value">{stats.total}</div>
              <div className="stat-label">Total Reports</div>
            </div>
            <div className="stat-card stat-allow">
              <div className="stat-icon">✓</div>
              <div className="stat-info">
                <div className="stat-value">{stats.allowed}</div>
                <div className="stat-label">Allowed</div>
              </div>
            </div>
            <div className="stat-card stat-review">
              <div className="stat-icon">!</div>
              <div className="stat-info">
                <div className="stat-value">{stats.review}</div>
                <div className="stat-label">Review</div>
              </div>
            </div>
            <div className="stat-card stat-block">
              <div className="stat-icon">✕</div>
              <div className="stat-info">
                <div className="stat-value">{stats.blocked}</div>
                <div className="stat-label">Blocked</div>
              </div>
            </div>
          </div>
        )}

      {/* Reports List */}
      <section className="reports-section">
        {isLoading ? (
          <div className="loading-state">
            <div className="loading-spinner" />
            <p>Loading reports...</p>
          </div>
        ) : reports.length === 0 ? (
          <div className="empty-state">
            <div className="empty-icon">📋</div>
            <h3>No Reports Yet</h3>
            <p>Scan an extension to generate a security report</p>
            <Button onClick={() => navigate("/scanner")}>Start Scanning</Button>
          </div>
        ) : (
          <div className="reports-list">
            {reports.map((report, index) => {
              const verdict = getGovernanceVerdict(report);
              const verdictStyle = getVerdictStyle(verdict);
              const extensionName = report.extension_name || report.extensionName || 
                                   report.extension_id || report.extensionId;
              const extensionId = report.extension_id || report.extensionId;
              const timestamp = new Date(report.timestamp);

              return (
                <Card key={index} className={`report-card ${verdictStyle.className}`}>
                  <div className="card-layout">
                    {/* Verdict Badge */}
                    <div className={`verdict-indicator ${verdictStyle.className}`}>
                      <span className="verdict-icon">{verdictStyle.icon}</span>
                    </div>

                    {/* Extension Info */}
                    <div className="extension-info">
                      <h3 className="extension-name">{extensionName}</h3>
                      <p className="scan-date">
                        {timestamp.toLocaleDateString(undefined, {
                          month: 'short',
                          day: 'numeric',
                          year: 'numeric'
                        })} at {timestamp.toLocaleTimeString(undefined, {
                          hour: '2-digit',
                          minute: '2-digit'
                        })}
                      </p>
                    </div>

                    {/* Verdict */}
                    <div className="verdict-section">
                      <Badge className={`verdict-badge ${verdictStyle.className}`}>
                        {verdict}
                      </Badge>
                    </div>

                    {/* Actions */}
                    <div className="actions-section">
                      <Button 
                        variant="outline" 
                        size="sm"
                        onClick={() => handleViewReport(extensionId)}
                        className="view-btn"
                      >
                        View Details
                      </Button>
                      <Button 
                        variant="ghost" 
                        size="sm"
                        onClick={() => handleDownloadPDF(extensionId)}
                        className="pdf-btn"
                      >
                        PDF
                      </Button>
                    </div>
                  </div>
                </Card>
              );
            })}
          </div>
        )}
      </section>

        {/* Info Footer */}
        <footer className="info-footer">
          <div className="info-item">
            <span className="info-icon">⚖️</span>
            <div>
              <strong>Consistent Analysis</strong>
              <p>Same input → same verdict, every time</p>
            </div>
          </div>
          <div className="info-item">
            <span className="info-icon">📎</span>
            <div>
              <strong>Evidence Chain</strong>
              <p>Code citations with file paths and line numbers</p>
            </div>
          </div>
          <div className="info-item">
            <span className="info-icon">📦</span>
            <div>
              <strong>Export Bundle</strong>
              <p>Download reports for IT workflows</p>
            </div>
          </div>
        </footer>
      </div>
    </div>
  );
};

export default ReportsPage;
