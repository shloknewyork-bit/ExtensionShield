import React, { useEffect, useState } from "react";
import { useParams, useNavigate, Link } from "react-router-dom";
import { Button } from "../../components/ui/button";
import { Badge } from "../../components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "../../components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "../../components/ui/tabs";
import { Download, X, Clock, TrendingUp, TrendingDown, Minus, Copy, ChevronDown, ChevronUp } from "lucide-react";
import FileViewerModal from "../../components/FileViewerModal";
import realScanService from "../../services/realScanService";
import databaseService from "../../services/databaseService";
import { getRiskLevel } from "../../utils/signalMapper";
import { 
  normalizeScanResultSafe, 
  validateEvidenceIntegrity,
  isDevelopmentMode 
} from "../../utils/normalizeScanResult";
import "./ReportDetailPage.scss";

// -----------------------------------------------------------------------------
// New UI renderer for backend `report_view_model` (production payload)
// -----------------------------------------------------------------------------
const badgeVariantForRisk = (risk) => {
  const r = String(risk || "").toUpperCase();
  if (r.includes("HIGH") || r.includes("CRITICAL") || r === "FAIL") return "destructive";
  if (r.includes("MEDIUM") || r === "WARN") return "secondary";
  if (r.includes("LOW") || r === "PASS") return "default";
  return "outline";
};

const ReportViewModelDetail = ({ report, extensionId, onExportPdf }) => {
  const [mode, setMode] = useState("simple"); // simple | advanced

  const meta = report?.meta || {};
  const scorecard = report?.scorecard || {};
  const highlights = report?.highlights || {};
  const impactCards = Array.isArray(report?.impact_cards) ? report.impact_cards : [];
  const privacy = report?.privacy_snapshot || {};

  const why = Array.isArray(highlights?.why_this_score) ? highlights.why_this_score : [];
  const watch = Array.isArray(highlights?.what_to_watch) ? highlights.what_to_watch : [];

  return (
    <div className="report-detail-page">
      <div className="report-bg-effects">
        <div className="report-bg-gradient report-gradient-1" />
        <div className="report-bg-gradient report-gradient-2" />
      </div>

      <div className="report-content">
        <div className="report-nav" style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
          <Link to="/reports" className="back-link">← Back to Reports</Link>
          <div style={{ display: "flex", gap: "0.5rem" }}>
            <Button variant="outline" size="sm" onClick={onExportPdf}>
              <Download size={16} />
              PDF
            </Button>
          </div>
        </div>

        <Card className="content-card">
          <CardHeader>
            <CardTitle style={{ display: "flex", justifyContent: "space-between", gap: "1rem", flexWrap: "wrap" }}>
              <span>{meta?.name || "Extension Report"}</span>
              <span style={{ display: "flex", gap: "0.5rem", alignItems: "center" }}>
                <Badge variant="outline">{extensionId}</Badge>
                <Badge variant={badgeVariantForRisk(scorecard?.score_label)}>{scorecard?.score_label || "UNKNOWN"}</Badge>
                <Badge variant="outline">Confidence: {scorecard?.confidence || "UNKNOWN"}</Badge>
              </span>
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div style={{ display: "flex", gap: "1rem", alignItems: "baseline", flexWrap: "wrap" }}>
              <div style={{ fontSize: "2rem", fontWeight: 700 }}>
                {Number.isFinite(scorecard?.score) ? scorecard.score : 0}
                <span style={{ fontSize: "1rem", opacity: 0.7 }}>/100</span>
              </div>
              <div style={{ fontSize: "1rem", opacity: 0.9 }}>{scorecard?.one_liner || ""}</div>
            </div>

            <div style={{ marginTop: "1rem", display: "flex", gap: "0.5rem" }}>
              <Button
                variant={mode === "simple" ? "default" : "outline"}
                size="sm"
                onClick={() => setMode("simple")}
              >
                Simple
              </Button>
              <Button
                variant={mode === "advanced" ? "default" : "outline"}
                size="sm"
                onClick={() => setMode("advanced")}
              >
                Advanced
              </Button>
            </div>
          </CardContent>
        </Card>

        <div style={{ marginTop: "1rem", display: "grid", gridTemplateColumns: "1fr", gap: "1rem" }}>
          <Card>
            <CardHeader>
              <CardTitle>Why this score</CardTitle>
            </CardHeader>
            <CardContent>
              {why.length > 0 ? (
                <ul style={{ marginLeft: "1rem", listStyle: "disc" }}>
                  {why.slice(0, 3).map((item, idx) => <li key={idx}>{item}</li>)}
                </ul>
              ) : (
                <div style={{ opacity: 0.7 }}>No highlights available.</div>
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>What to watch</CardTitle>
            </CardHeader>
            <CardContent>
              {watch.length > 0 ? (
                <ul style={{ marginLeft: "1rem", listStyle: "disc" }}>
                  {watch.slice(0, 2).map((item, idx) => <li key={idx}>{item}</li>)}
                </ul>
              ) : (
                <div style={{ opacity: 0.7 }}>No watch items.</div>
              )}
            </CardContent>
          </Card>
        </div>

        <div style={{ marginTop: "1rem", display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(260px, 1fr))", gap: "1rem" }}>
          {impactCards.slice(0, 3).map((c) => (
            <Card key={c.id}>
              <CardHeader>
                <CardTitle style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: "0.5rem" }}>
                  <span>{c.title || c.id}</span>
                  <Badge variant={badgeVariantForRisk(c.risk_level)}>{c.risk_level || "UNKNOWN"}</Badge>
                </CardTitle>
              </CardHeader>
              <CardContent>
                {Array.isArray(c.bullets) && c.bullets.length > 0 ? (
                  <ul style={{ marginLeft: "1rem", listStyle: "disc" }}>
                    {c.bullets.map((b, idx) => <li key={idx}>{b}</li>)}
                  </ul>
                ) : (
                  <div style={{ opacity: 0.7 }}>No details available.</div>
                )}

                {Array.isArray(c.mitigations) && c.mitigations.length > 0 && (
                  <div style={{ marginTop: "0.75rem" }}>
                    <div style={{ fontWeight: 600, marginBottom: "0.25rem" }}>Mitigations</div>
                    <ul style={{ marginLeft: "1rem", listStyle: "disc" }}>
                      {c.mitigations.map((m, idx) => <li key={idx}>{m}</li>)}
                    </ul>
                  </div>
                )}
              </CardContent>
            </Card>
          ))}
        </div>

        {mode === "advanced" && (
          <div style={{ marginTop: "1rem", display: "grid", gridTemplateColumns: "1fr", gap: "1rem" }}>
            <Card>
              <CardHeader>
                <CardTitle>Privacy &amp; Compliance</CardTitle>
              </CardHeader>
              <CardContent>
                {privacy?.privacy_snapshot && (
                  <div style={{ marginBottom: "0.75rem", opacity: 0.9 }}>{privacy.privacy_snapshot}</div>
                )}

                {Array.isArray(privacy?.governance_checks) && privacy.governance_checks.length > 0 ? (
                  <div style={{ overflowX: "auto" }}>
                    <table style={{ width: "100%", borderCollapse: "collapse" }}>
                      <thead>
                        <tr style={{ textAlign: "left", borderBottom: "1px solid rgba(255,255,255,0.08)" }}>
                          <th style={{ padding: "0.5rem" }}>Check</th>
                          <th style={{ padding: "0.5rem" }}>Status</th>
                          <th style={{ padding: "0.5rem" }}>Note</th>
                        </tr>
                      </thead>
                      <tbody>
                        {privacy.governance_checks.map((row, idx) => (
                          <tr key={idx} style={{ borderBottom: "1px solid rgba(255,255,255,0.06)" }}>
                            <td style={{ padding: "0.5rem" }}>{row?.check || ""}</td>
                            <td style={{ padding: "0.5rem" }}>
                              <Badge variant={badgeVariantForRisk(row?.status)}>{row?.status || "UNKNOWN"}</Badge>
                            </td>
                            <td style={{ padding: "0.5rem", opacity: 0.9 }}>{row?.note || ""}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                ) : (
                  <div style={{ opacity: 0.7 }}>No governance checks available.</div>
                )}
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle>Evidence</CardTitle>
              </CardHeader>
              <CardContent>
                <details>
                  <summary style={{ cursor: "pointer", userSelect: "none" }}>Show evidence JSON</summary>
                  <pre
                    style={{
                      marginTop: "0.75rem",
                      whiteSpace: "pre-wrap",
                      wordBreak: "break-word",
                      fontFamily: "ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, 'Liberation Mono', 'Courier New', monospace",
                      fontSize: "0.85rem",
                      opacity: 0.95
                    }}
                  >
                    {JSON.stringify({ evidence: report?.evidence, raw: report?.raw }, null, 2)}
                  </pre>
                </details>
              </CardContent>
            </Card>
          </div>
        )}
      </div>
    </div>
  );
};

// Version History Component
const VersionHistorySection = ({ currentVersion, currentScore, extensionId, scanHistory }) => {
  // Format date
  const formatDate = (timestamp) => {
    if (!timestamp) return "Unknown";
    const date = new Date(timestamp);
    return date.toLocaleDateString(undefined, { 
      year: 'numeric', 
      month: 'short', 
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    });
  };

  // Calculate score delta indicator
  const getScoreDelta = (currentScore, previousScore) => {
    if (previousScore === null || previousScore === undefined) return null;
    const delta = currentScore - previousScore;
    if (delta > 0) return { direction: 'up', value: delta, icon: <TrendingUp size={14} /> };
    if (delta < 0) return { direction: 'down', value: Math.abs(delta), icon: <TrendingDown size={14} /> };
    return { direction: 'same', value: 0, icon: <Minus size={14} /> };
  };

  // If no history, show empty state
  if (!scanHistory || scanHistory.length <= 1) {
    return (
      <div className="version-history-section">
        <h3 className="section-title">
          <Clock size={18} />
          Version & Risk History
        </h3>
        <div className="version-empty-state">
          <div className="empty-icon">📊</div>
          <h4>No version history available</h4>
          <p>When this extension is scanned again with a different version, you'll see changes tracked here.</p>
        </div>
      </div>
    );
  }

  return (
    <div className="version-history-section">
      <h3 className="section-title">
        <Clock size={18} />
        Version & Risk History
      </h3>
      
      <div className="version-timeline">
        {scanHistory.map((scan, index) => {
          const isLatest = index === 0;
          const previousScan = scanHistory[index + 1];
          const scoreDelta = previousScan ? getScoreDelta(scan.score, previousScan.score) : null;
          const riskLevel = getRiskLevel(scan.score);

          return (
            <div key={scan.timestamp || index} className={`version-item ${isLatest ? 'latest' : ''}`}>
              <div className="version-marker">
                <div className="marker-dot" />
                {index < scanHistory.length - 1 && <div className="marker-line" />}
              </div>
              
              <div className="version-content">
                <div className="version-header">
                  <span className="version-badge">v{scan.version || 'Unknown'}</span>
                  {isLatest && <span className="latest-badge">Current</span>}
                  <span className="version-date">{formatDate(scan.timestamp)}</span>
                </div>
                
                <div className="version-stats">
                  <div className={`score-pill risk-${riskLevel.toLowerCase()}`}>
                    <span className="score-value">{scan.score ?? '—'}</span>
                    <span className="score-label">/100</span>
                    {scoreDelta && (
                      <span className={`score-delta delta-${scoreDelta.direction}`}>
                        {scoreDelta.icon}
                        {scoreDelta.value > 0 && scoreDelta.value}
                      </span>
                    )}
                  </div>
                  
                  <span className={`risk-label risk-${riskLevel.toLowerCase()}`}>
                    {riskLevel}
                  </span>
                </div>

                {/* Show what changed if we have previous scan data */}
                {previousScan && scoreDelta && scoreDelta.value !== 0 && (
                  <div className="version-changes">
                    <span className="changes-label">Changes from v{previousScan.version}:</span>
                    <ul className="changes-list">
                      {scoreDelta.direction === 'up' && (
                        <li className="change-positive">Security score improved by {scoreDelta.value} points</li>
                      )}
                      {scoreDelta.direction === 'down' && (
                        <li className="change-negative">Security score decreased by {scoreDelta.value} points</li>
                      )}
                    </ul>
                  </div>
                )}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};

// Report Data Unavailable Component - shown when normalization fails
const ReportDataUnavailable = ({ extensionId, rawData, error }) => {
  const [showRawJson, setShowRawJson] = useState(false);
  const isDevMode = isDevelopmentMode();
  
  const handleCopyJson = () => {
    try {
      const jsonStr = JSON.stringify(rawData, null, 2);
      navigator.clipboard.writeText(jsonStr);
      alert("Raw JSON copied to clipboard");
    } catch (e) {
      console.error("Failed to copy JSON:", e);
    }
  };
  
  return (
    <div className="report-data-unavailable">
      <div className="unavailable-icon">⚠️</div>
      <h2>Report Data Unavailable</h2>
      <p>We couldn't process the scan data for this extension.</p>
      
      <div className="extension-id-display">
        <span className="label">Extension ID:</span>
        <code>{extensionId || "Unknown"}</code>
      </div>
      
      {error && (
        <div className="error-message">
          <span className="label">Error:</span>
          <span>{error}</span>
        </div>
      )}
      
      {isDevMode && rawData && (
        <div className="dev-tools">
          <div className="dev-tools-header">
            <span className="dev-label">🛠️ Developer Tools</span>
            <Button 
              variant="ghost" 
              size="sm" 
              onClick={handleCopyJson}
              className="copy-btn"
            >
              <Copy size={14} />
              Copy JSON
            </Button>
          </div>
          
          <button 
            className="toggle-raw-json"
            onClick={() => setShowRawJson(!showRawJson)}
          >
            {showRawJson ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
            {showRawJson ? "Hide" : "Show"} Raw JSON
          </button>
          
          {showRawJson && (
            <pre className="raw-json-display">
              {JSON.stringify(rawData, null, 2)}
            </pre>
          )}
        </div>
      )}
    </div>
  );
};

// Permission to capability mapping with icons
const CAPABILITY_MAP = {
  tabCapture: { icon: "🎥", label: "Screen Capture", desc: "Can record your screen or tabs", risk: "medium" },
  tabs: { icon: "📑", label: "Tab Access", desc: "Can see your open tabs", risk: "low" },
  storage: { icon: "💾", label: "Data Storage", desc: "Stores data on your device", risk: "low" },
  cookies: { icon: "🍪", label: "Cookie Access", desc: "Can read website cookies", risk: "medium" },
  history: { icon: "📜", label: "Browsing History", desc: "Can see your browsing history", risk: "high" },
  bookmarks: { icon: "🔖", label: "Bookmarks", desc: "Can access your bookmarks", risk: "low" },
  downloads: { icon: "📥", label: "Downloads", desc: "Can manage downloads", risk: "medium" },
  geolocation: { icon: "📍", label: "Location", desc: "Can access your location", risk: "high" },
  notifications: { icon: "🔔", label: "Notifications", desc: "Can send notifications", risk: "low" },
  webRequest: { icon: "🌐", label: "Network Access", desc: "Can monitor network traffic", risk: "high" },
  activeTab: { icon: "👁️", label: "Active Tab", desc: "Can see current tab content", risk: "medium" },
  clipboardRead: { icon: "📋", label: "Clipboard Read", desc: "Can read your clipboard", risk: "high" },
  clipboardWrite: { icon: "✏️", label: "Clipboard Write", desc: "Can write to clipboard", risk: "low" },
  management: { icon: "⚙️", label: "Extension Management", desc: "Can manage other extensions", risk: "high" },
  "<all_urls>": { icon: "🌍", label: "All Websites", desc: "Access to all websites", risk: "high" },
  identity: { icon: "👤", label: "Identity", desc: "Can access your identity", risk: "high" },
  alarms: { icon: "⏰", label: "Scheduled Tasks", desc: "Can run scheduled tasks", risk: "low" },
  contextMenus: { icon: "📝", label: "Context Menu", desc: "Adds right-click options", risk: "low" },
  scripting: { icon: "💻", label: "Script Injection", desc: "Can inject scripts into pages", risk: "high" },
};

const ReportDetailPage = () => {
  const { reportId } = useParams();
  const navigate = useNavigate();

  const [scanResults, setScanResults] = useState(null);
  const [rawScanData, setRawScanData] = useState(null); // Keep raw data for error display
  const [reportViewModel, setReportViewModel] = useState(null); // Normalized view model
  const [uiReportViewModel, setUiReportViewModel] = useState(null); // Backend report_view_model
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState(null);
  const [normalizationError, setNormalizationError] = useState(null);
  const [showInfoPopup, setShowInfoPopup] = useState(null);
  const [fileViewerModal, setFileViewerModal] = useState({ isOpen: false, file: null });
  const [versionHistory, setVersionHistory] = useState([]);

  useEffect(() => {
    loadReportData(reportId);
  }, [reportId]);

  const loadReportData = async (extId) => {
    try {
      setIsLoading(true);
      setNormalizationError(null);
      
      // Fetch raw data
      let rawResults = await databaseService.getScanResult(extId);
      if (!rawResults) {
        rawResults = await realScanService.getRealScanResults(extId);
      }
      
      // Store raw data for error display
      setRawScanData(rawResults);

      // Prefer backend UI payload when available
      const backendReportVM =
        rawResults && typeof rawResults === "object" && rawResults.report_view_model && typeof rawResults.report_view_model === "object"
          ? rawResults.report_view_model
          : null;
      setUiReportViewModel(backendReportVM);
      
      // Format for legacy compatibility
      let results = rawResults;
      if (results && !results.files) {
        results = realScanService.formatRealResults(results);
      }
      setScanResults(results);
      
      // Try to normalize using safe normalizer (won't throw)
      const viewModel = normalizeScanResultSafe(rawResults);
      setReportViewModel(viewModel);
      
      if (!viewModel) {
        setNormalizationError("Failed to normalize scan result data");
        console.error("[ReportDetailPage] normalizeScanResultSafe returned null");
      } else {
        // Validate evidence integrity and log warnings
        const validation = validateEvidenceIntegrity(viewModel);
        if (!validation.valid) {
          validation.warnings.forEach(warning => {
            console.warn(`[ReportDetailPage] Evidence validation warning: ${warning}`);
          });
        }
      }
      
      // Build version history from current scan (in future, this could come from API)
      // For now, we show current version as the only entry
      const currentHistory = [{
        version: results?.version || results?.manifest?.version || 'Unknown',
        score: results?.overall_security_score || results?.securityScore || 0,
        timestamp: results?.timestamp,
        risk_level: results?.overall_risk || results?.riskLevel,
        permissions_count: results?.permissions?.length || 0,
        findings_count: results?.total_findings || results?.totalFindings || 0
      }];
      setVersionHistory(currentHistory);
      
      setError(null);
    } catch (err) {
      setError("Failed to load report data");
      console.error(err);
    } finally {
      setIsLoading(false);
    }
  };

  const handleViewFile = (file) => {
    setFileViewerModal({ isOpen: true, file });
  };

  const getFileContent = async (extensionId, filePath) => {
    return await realScanService.getFileContent(extensionId, filePath);
  };

  const handleExportPDF = () => {
    if (reportId) {
      const baseURL = import.meta.env.VITE_API_URL || "";
      window.open(`${baseURL}/api/scan/report/${reportId}`, '_blank');
    }
  };

  // Get trust level info
  const getTrustLevel = (score) => {
    if (score >= 80) return { label: "Trusted", color: "green", icon: "✓" };
    if (score >= 60) return { label: "Moderate", color: "yellow", icon: "!" };
    if (score >= 40) return { label: "Caution", color: "orange", icon: "⚡" };
    return { label: "Warning", color: "red", icon: "⚠" };
  };

  // Parse capabilities from permissions
  const getCapabilities = (permissions) => {
    if (!permissions) return [];
    return permissions.map(p => {
      const permName = p.name || p;
      const mapped = CAPABILITY_MAP[permName];
      if (mapped) {
        return { ...mapped, name: permName, originalRisk: p.risk };
      }
      return {
        icon: "🔧",
        label: permName,
        desc: p.description || "Extension capability",
        risk: p.risk?.toLowerCase() || "low",
        name: permName
      };
    });
  };

  // Loading state
  if (isLoading) {
    return (
      <div className="report-detail-page">
        <div className="report-bg-effects">
          <div className="report-bg-gradient report-gradient-1" />
          <div className="report-bg-gradient report-gradient-2" />
        </div>
        <div className="report-content">
          <div className="loading-container">
            <div className="loading-spinner"></div>
            <p>Analyzing extension...</p>
          </div>
        </div>
      </div>
    );
  }

  // If backend report_view_model is present, render the production report UI
  if (uiReportViewModel) {
    return (
      <ReportViewModelDetail
        report={uiReportViewModel}
        extensionId={reportId}
        onExportPdf={handleExportPDF}
      />
    );
  }

  // Error state - no data at all
  if (!scanResults && error) {
    return (
      <div className="report-detail-page">
        <div className="report-bg-effects">
          <div className="report-bg-gradient report-gradient-1" />
          <div className="report-bg-gradient report-gradient-2" />
        </div>
        <div className="report-content">
          <div className="error-container">
            <div className="error-icon">⚠️</div>
            <h2>Report Not Found</h2>
            <p>{error}</p>
            <Button onClick={() => navigate("/reports")}>Back to Reports</Button>
          </div>
        </div>
      </div>
    );
  }

  // Normalization failed - show data unavailable with debug info
  if (scanResults && !reportViewModel) {
    return (
      <div className="report-detail-page">
        <div className="report-bg-effects">
          <div className="report-bg-gradient report-gradient-1" />
          <div className="report-bg-gradient report-gradient-2" />
        </div>
        <div className="report-content">
          <div className="report-nav">
            <Link to="/reports" className="back-link">← Back to Reports</Link>
          </div>
          <ReportDataUnavailable 
            extensionId={reportId}
            rawData={rawScanData}
            error={normalizationError}
          />
          <div className="error-actions">
            <Button onClick={() => navigate("/reports")}>Back to Reports</Button>
            <Button variant="outline" onClick={() => loadReportData(reportId)}>
              Retry
            </Button>
          </div>
        </div>
      </div>
    );
  }

  const trustLevel = getTrustLevel(scanResults?.securityScore || 0);
  const capabilities = getCapabilities(scanResults?.permissions);
  const highRiskCaps = capabilities.filter(c => c.risk === "high");

  // Determine overall behavior assessment
  const hasNetworkAccess = capabilities.some(c => ["webRequest", "<all_urls>", "Network Access"].includes(c.name));
  const hasDataAccess = capabilities.some(c => ["history", "cookies", "clipboardRead", "identity"].includes(c.name));
  const hasScreenCapture = capabilities.some(c => ["tabCapture", "Screen Capture"].includes(c.name) || c.label === "Screen Capture");

  // Info items for the popup
  const infoItems = [
    { icon: "🧩", label: "Extension Name", value: scanResults?.name || "Unknown" },
    { icon: "👤", label: "Developer", value: scanResults?.developer || "Unknown" },
    { icon: "📦", label: "Version", value: scanResults?.version || "Unknown" },
    { icon: "📅", label: "Last Updated", value: scanResults?.lastUpdated || "Unknown" },
  ];

  return (
    <div className="report-detail-page">
      {/* Background Effects */}
      <div className="report-bg-effects">
        <div className="report-bg-gradient report-gradient-1" />
        <div className="report-bg-gradient report-gradient-2" />
      </div>

      {/* Content */}
      <div className="report-content">
        {/* Navigation */}
        <div className="report-nav">
          <Link to="/reports" className="back-link">← Back to Reports</Link>
          <div className="nav-actions">
            <Button variant="outline" size="sm" onClick={() => navigate(`/reports/${reportId}`)}>
              Full Analysis
            </Button>
            <Button variant="outline" size="sm" onClick={handleExportPDF}>
              📥 PDF
            </Button>
          </div>
        </div>

        {/* Unified Hero Section - Centered */}
        <section className="report-hero">
          {/* Extension Identity */}
          <div className="hero-identity">
            <h1 className="hero-title">{scanResults?.name || "Extension Report"}</h1>
            <div className="hero-meta">
              <code className="extension-id">{reportId}</code>
              {scanResults?.version && <span className="version-badge">v{scanResults.version}</span>}
              <button 
                className="info-trigger-inline"
                onClick={() => setShowInfoPopup(!showInfoPopup)}
                title="View extension details"
              >
                ℹ️
              </button>
            </div>
          </div>

          {/* Trust Score Card */}
          <div className={`trust-card trust-${trustLevel.color}`}>
            <div className={`trust-circle trust-${trustLevel.color}`}>
              <span className="trust-number">{scanResults?.securityScore || 0}</span>
              <span className="trust-max">/100</span>
            </div>
            
            <div className="trust-details">
              <span className={`trust-badge trust-${trustLevel.color}`}>
                {trustLevel.icon} {trustLevel.label}
              </span>
              
              <div className={`verdict-banner verdict-${trustLevel.color}`}>
                <span className="verdict-icon">
                  {scanResults?.securityScore >= 80 ? "✅" : scanResults?.securityScore >= 60 ? "⚠️" : "🚨"}
                </span>
                <span className="verdict-text">
                  {scanResults?.securityScore >= 80 
                    ? "Safe to use" 
                    : scanResults?.securityScore >= 60 
                      ? "Review recommended"
                      : "Proceed with caution"}
                </span>
              </div>
            </div>
          </div>

          {/* Scan Meta */}
          <div className="scan-meta">
            <span className="scan-timestamp">
              🕐 {scanResults?.timestamp 
                ? new Date(scanResults.timestamp).toLocaleDateString(undefined, { month: 'short', day: 'numeric' })
                : 'Recently'}
            </span>
            <span className="meta-dot">•</span>
            <span className="scan-files">
              📁 {scanResults?.files?.length || 0} files analyzed
            </span>
          </div>
        </section>

        {/* Info Popup */}
        {showInfoPopup && (
          <div className="info-popup-overlay" onClick={() => setShowInfoPopup(false)}>
            <div className="info-popup" onClick={(e) => e.stopPropagation()}>
              <div className="info-popup-header">
                <h3>Extension Details</h3>
                <button className="close-popup" onClick={() => setShowInfoPopup(false)}>
                  <X size={18} />
                </button>
              </div>
              <div className="info-popup-content">
                {infoItems.map((item, idx) => (
                  <div key={idx} className="info-popup-item">
                    <span className="info-popup-icon">{item.icon}</span>
                    <div className="info-popup-text">
                      <span className="info-popup-label">{item.label}</span>
                      <span className="info-popup-value">{item.value}</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {/* Tabs for Details - Right after Trust Score */}
        <Tabs defaultValue="summary" className="results-tabs">
          <TabsList className="tabs-list tabs-list-5">
            <TabsTrigger value="summary" className="tab-with-icon">
              <span className="tab-icon">📋</span>
              <span className="tab-label">Summary</span>
            </TabsTrigger>
            <TabsTrigger value="permissions" className="tab-with-icon">
              <span className="tab-icon">👁️</span>
              <span className="tab-label">Permissions</span>
            </TabsTrigger>
            <TabsTrigger value="security" className="tab-with-icon">
              <span className="tab-icon">🛡️</span>
              <span className="tab-label">Security</span>
            </TabsTrigger>
            <TabsTrigger value="history" className="tab-with-icon">
              <span className="tab-icon">📊</span>
              <span className="tab-label">History</span>
            </TabsTrigger>
            <TabsTrigger value="actions" className="tab-with-icon">
              <span className="tab-icon">✅</span>
              <span className="tab-label">Actions</span>
            </TabsTrigger>
          </TabsList>

          {/* Summary Tab */}
          <TabsContent value="summary" className="tab-content">
            <Card className="content-card">
              <CardContent className="summary-content">
                <div className="summary-icon">💡</div>
                <div className="summary-text">
                  <h3>Analysis Summary</h3>
                  <p>{scanResults?.executiveSummary || "This extension has been analyzed for security concerns."}</p>
                </div>
              </CardContent>
            </Card>
            
            {/* Quick Risk Indicators in Summary */}
            {(highRiskCaps.length > 0 || scanResults?.totalFindings > 0) && (
              <div className="risk-alerts">
                {highRiskCaps.length > 0 && (
                  <div className="risk-alert warning">
                    <span className="alert-icon">⚠️</span>
                    <span>{highRiskCaps.length} sensitive permission{highRiskCaps.length > 1 ? 's' : ''}</span>
                  </div>
                )}
                {scanResults?.totalFindings > 0 && (
                  <div className="risk-alert danger">
                    <span className="alert-icon">🚨</span>
                    <span>{scanResults.totalFindings} issue{scanResults.totalFindings > 1 ? 's' : ''} found</span>
                  </div>
                )}
              </div>
            )}
          </TabsContent>

          {/* Permissions Tab - What This Extension Can Do */}
          <TabsContent value="permissions" className="tab-content">
            <div className="permissions-overview">
              {/* Behavior Cards */}
              <div className="behavior-cards">
                <div className={`behavior-card ${hasNetworkAccess ? "active" : "inactive"}`}>
                  <span className="behavior-icon">🌐</span>
                  <span className="behavior-label">Network</span>
                  <span className={`behavior-status ${hasNetworkAccess ? "yes" : "no"}`}>
                    {hasNetworkAccess ? "Yes" : "No"}
                  </span>
                </div>
                <div className={`behavior-card ${hasDataAccess ? "active" : "inactive"}`}>
                  <span className="behavior-icon">📊</span>
                  <span className="behavior-label">Data</span>
                  <span className={`behavior-status ${hasDataAccess ? "yes" : "no"}`}>
                    {hasDataAccess ? "Yes" : "No"}
                  </span>
                </div>
                <div className={`behavior-card ${hasScreenCapture ? "active" : "inactive"}`}>
                  <span className="behavior-icon">🎥</span>
                  <span className="behavior-label">Screen</span>
                  <span className={`behavior-status ${hasScreenCapture ? "yes" : "no"}`}>
                    {hasScreenCapture ? "Yes" : "No"}
                  </span>
                </div>
                <div className={`behavior-card ${highRiskCaps.length > 0 ? "active warning" : "inactive"}`}>
                  <span className="behavior-icon">⚠️</span>
                  <span className="behavior-label">Sensitive</span>
                  <span className={`behavior-status ${highRiskCaps.length > 0 ? "yes" : "no"}`}>
                    {highRiskCaps.length || "None"}
                  </span>
                </div>
              </div>

              {/* Capabilities List */}
              {capabilities.length > 0 && (
                <div className="capability-section">
                  <h4 className="capability-section-title">All Permissions</h4>
                  <div className="capability-list">
                    {capabilities.map((cap, idx) => (
                      <div key={idx} className={`capability-chip risk-${cap.risk}`}>
                        <span className="chip-icon">{cap.icon}</span>
                        <span className="chip-label">{cap.label}</span>
                        <span className="chip-risk">{cap.risk === "high" ? "🔴" : cap.risk === "medium" ? "🟡" : "🟢"}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {capabilities.length === 0 && (
                <div className="no-capabilities">
                  <span>✨</span>
                  <p>Minimal permissions required</p>
                </div>
              )}
            </div>
          </TabsContent>

          {/* Security Tab */}
          <TabsContent value="security" className="tab-content">
            <div className="security-checks">
              <div className={`check-item ${(scanResults?.virustotalAnalysis?.total_malicious || 0) === 0 ? "pass" : "fail"}`}>
                <span className="check-icon">{(scanResults?.virustotalAnalysis?.total_malicious || 0) === 0 ? "✅" : "❌"}</span>
                <div className="check-info">
                  <span className="check-name">Malware Free</span>
                  <span className="check-desc">No known malware detected</span>
                </div>
              </div>
              <div className={`check-item ${(scanResults?.entropyAnalysis?.obfuscated_files || 0) === 0 ? "pass" : "warn"}`}>
                <span className="check-icon">{(scanResults?.entropyAnalysis?.obfuscated_files || 0) === 0 ? "✅" : "⚠️"}</span>
                <div className="check-info">
                  <span className="check-name">Code Transparency</span>
                  <span className="check-desc">{(scanResults?.entropyAnalysis?.obfuscated_files || 0) === 0 ? "Code is readable" : "Some code may be hidden"}</span>
                </div>
              </div>
              <div className={`check-item ${highRiskCaps.length === 0 ? "pass" : highRiskCaps.length <= 2 ? "warn" : "fail"}`}>
                <span className="check-icon">{highRiskCaps.length === 0 ? "✅" : highRiskCaps.length <= 2 ? "⚠️" : "❌"}</span>
                <div className="check-info">
                  <span className="check-name">Permission Scope</span>
                  <span className="check-desc">{highRiskCaps.length === 0 ? "Minimal permissions" : `${highRiskCaps.length} sensitive permission(s)`}</span>
                </div>
              </div>
            </div>
          </TabsContent>

          {/* History Tab */}
          <TabsContent value="history" className="tab-content">
            <VersionHistorySection 
              currentVersion={scanResults?.version || scanResults?.manifest?.version}
              currentScore={scanResults?.securityScore || scanResults?.overall_security_score || 0}
              extensionId={reportId}
              scanHistory={versionHistory}
            />
          </TabsContent>

          {/* Actions Tab */}
          <TabsContent value="actions" className="tab-content">
            <div className="actions-content">
              {scanResults?.securityScore >= 80 ? (
                <div className="action-card success">
                  <span className="action-icon">✅</span>
                  <div className="action-text">
                    <h4>Safe to Use</h4>
                    <p>This extension appears safe. No immediate action required.</p>
                  </div>
                </div>
              ) : scanResults?.securityScore >= 50 ? (
                <div className="action-card warning">
                  <span className="action-icon">⚡</span>
                  <div className="action-text">
                    <h4>Review Recommended</h4>
                    <p>Consider reviewing the capabilities before installing.</p>
                  </div>
                </div>
              ) : (
                <div className="action-card danger">
                  <span className="action-icon">⚠️</span>
                  <div className="action-text">
                    <h4>Proceed with Caution</h4>
                    <p>This extension has concerning characteristics.</p>
                  </div>
                </div>
              )}

              <div className="action-list">
                <div className="action-item">
                  <span>🔒</span>
                  <span>Review permissions before installing</span>
                </div>
                <div className="action-item">
                  <span>👤</span>
                  <span>Verify the developer is trustworthy</span>
                </div>
                <div className="action-item">
                  <span>⭐</span>
                  <span>Check user reviews in Chrome Web Store</span>
                </div>
              </div>

              {/* Export */}
              <Button onClick={handleExportPDF} className="export-btn">
                <Download size={16} />
                Download Full Report
              </Button>
            </div>
          </TabsContent>
        </Tabs>

        <FileViewerModal
          isOpen={fileViewerModal.isOpen}
          onClose={() => setFileViewerModal({ isOpen: false, file: null })}
          file={fileViewerModal.file}
          extensionId={reportId}
          onGetFileContent={getFileContent}
        />
      </div>
    </div>
  );
};

export default ReportDetailPage;
