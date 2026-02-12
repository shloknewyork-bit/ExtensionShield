import React, { useState, useEffect, useMemo, useRef } from "react";
import { useNavigate } from "react-router-dom";
import { useAuth } from "../context/AuthContext";
import databaseService from "../services/databaseService";
import {
  getRiskColorClass,
  getSignalColorClass,
} from "../utils/signalMapper";
import { enrichScans } from "../utils/scanEnrichment";
import { EXTENSION_ICON_PLACEHOLDER, getExtensionIconUrl } from "../utils/constants";
import SEOHead from "../components/SEOHead";
import "./ScanHistoryPage.scss";

// Tooltip component for signal chips
const SignalTooltip = ({ type, children }) => {
  const tooltips = {
    security: "Security: Technical vulnerabilities, SAST findings, and code quality analysis",
    privacy: "Privacy: Data collection risks, permissions analysis, and exfiltration detection",
    governance: "Governance: Policy compliance, behavioral consistency, and regulatory adherence",
    // Legacy tooltips for backward compatibility
    code: "Code Analysis: SAST scanning, entropy detection, and obfuscation checks",
    perms: "Permissions: Analysis of requested browser permissions and access levels",
    intel: "Threat Intel: VirusTotal scan results and malware detection flags"
  };

  return (
    <div className="signal-chip-wrapper" title={tooltips[type] || tooltips.code}>
      {children}
    </div>
  );
};

// Signal chip component
const SignalChip = ({ type, signal }) => {
  const labels = { 
    security: "Security", 
    privacy: "Privacy", 
    governance: "Gov",  // Shortened for space
    // Legacy labels for backward compatibility
    code: "Code", 
    perms: "Perms", 
    intel: "Intel" 
  };
  
  const icons = {
    security: (
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
      </svg>
    ),
    privacy: (
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
        <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
        <path d="M7 11V7a5 5 0 0 1 10 0v4" />
      </svg>
    ),
    governance: (
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
        <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
        <path d="M14 2v6h6" />
        <path d="M16 13H8" />
        <path d="M16 17H8" />
        <path d="M10 9H8" />
      </svg>
    ),
    // Legacy icons for backward compatibility
    code: (
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
        <polyline points="16,18 22,12 16,6" />
        <polyline points="8,6 2,12 8,18" />
      </svg>
    ),
    perms: (
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
      </svg>
    ),
    intel: (
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
        <circle cx="12" cy="12" r="10" />
        <line x1="12" y1="8" x2="12" y2="12" />
        <line x1="12" y1="16" x2="12.01" y2="16" />
      </svg>
    )
  };

  const colorClass = getSignalColorClass(signal?.level);

  return (
    <SignalTooltip type={type}>
      <div className={`signal-chip ${colorClass}`}>
        <span className="signal-icon">{icons[type] || icons.code}</span>
        <span className="signal-label">{labels[type] || labels.code}</span>
        <span className="signal-value">{signal?.label || "—"}</span>
      </div>
    </SignalTooltip>
  );
};

// Risk badge component
const RiskBadge = ({ level, score }) => {
  const colorClass = getRiskColorClass(level);
  return (
    <div className={`risk-badge ${colorClass}`}>
      <span className="risk-level">{level || "—"}</span>
    </div>
  );
};

// =============================================================================
// TESTING: Set to true to show scan history table without signing in (uses /api/recent).
// COMMENT OUT or set to false when login is required for production.
// =============================================================================
const SHOW_TABLE_WITHOUT_SIGN_IN = true;

/**
 * ScanHistoryPage Component
 * Displays viewing history of scanned extensions with same design as Scanner page.
 */
const ScanHistoryPage = () => {
  const [allScans, setAllScans] = useState([]);
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState("");
  const [debouncedSearch, setDebouncedSearch] = useState("");
  const [sortConfig, setSortConfig] = useState({ key: "timestamp", direction: "desc" });
  const [currentPage, setCurrentPage] = useState(1);
  const [rowsPerPage, setRowsPerPage] = useState(25);
  const [hoveredRow, setHoveredRow] = useState(null);
  const [copiedId, setCopiedId] = useState(null);
  const [dashboardStats, setDashboardStats] = useState({
    totalScans: { value: 0, sparkline: [0] },
    highRisk: { value: 0, sparkline: [0] },
    totalFiles: { value: 0, sparkline: [0] },
    totalVulnerabilities: { value: 0, sparkline: [0] },
    avgSecurityScore: 0,
    riskDistribution: { high: 0, medium: 0, low: 0 }
  });
  const tableWrapperRef = useRef(null);
  const navigate = useNavigate();
  const { isAuthenticated, openSignInModal, accessToken } = useAuth();

  const supabaseConfigured = Boolean(import.meta.env.VITE_SUPABASE_URL);
  const canLoadHistory = isAuthenticated || !supabaseConfigured || SHOW_TABLE_WITHOUT_SIGN_IN;

  // Debounce search for server-side API calls (searches Postgres)
  useEffect(() => {
    const t = setTimeout(() => setDebouncedSearch(searchTerm), 300);
    return () => clearTimeout(t);
  }, [searchTerm]);

  useEffect(() => {
    let isMounted = true;
    
    const loadHistory = async () => {
      if (!canLoadHistory) {
        if (isMounted) {
          setAllScans([]);
          setLoading(false);
        }
        return;
      }

      setLoading(true);
      
      // Safety timeout
      const safetyTimeout = setTimeout(() => {
        if (isMounted) {
          setLoading(false);
        }
      }, 3000);

      try {
        // Request timeout wrapper
        const timeoutPromise = new Promise((_, reject) =>
          setTimeout(() => reject(new Error('Request timeout')), 5000)
        );

        let history;
        if (isAuthenticated) {
          // Authenticated: use user-scoped /api/history (user_scan_history joined with scan_results)
          // Pass accessToken for Bearer auth; backend returns 401 if missing → we get []
          history = await Promise.race([
            databaseService.getScanHistory(100, accessToken),
            timeoutPromise
          ]);
        } else if (SHOW_TABLE_WITHOUT_SIGN_IN) {
          // Unauthenticated: use /api/recent (global recent scans; searches Postgres via ?search=)
          // Limit to 10 rows for public view - sign in required to see full history
          history = await Promise.race([
            databaseService.getRecentScans(10, debouncedSearch),
            timeoutPromise
          ]);
        } else {
          history = [];
        }
        
        // Load dashboard stats for charts (best-effort, don't block)
        if (isMounted) {
          databaseService.getDashboardMetrics()
            .then((metrics) => {
              if (isMounted) {
                setDashboardStats(metrics);
              }
            })
            .catch((err) => {
              // console.error("Error loading dashboard stats:", err); // prod: no console
            });
        }
        
        // Enrich scans using utility function (uses Promise.allSettled internally)
        const enrichedScans = await enrichScans(history);
        
        if (isMounted) {
          setAllScans(enrichedScans);
        }
      } catch (error) {
        // console.error("Failed to load scan history:", error); // prod: no console
        if (isMounted) {
          setAllScans([]);
        }
      } finally {
        clearTimeout(safetyTimeout);
        if (isMounted) {
          setLoading(false);
        }
      }
    };

    loadHistory();

    return () => {
      isMounted = false;
    };
  }, [isAuthenticated, accessToken, canLoadHistory, debouncedSearch]);

  // Handle scroll shadows for horizontal scrolling
  useEffect(() => {
    const tableWrapper = tableWrapperRef.current;
    if (!tableWrapper) return;

    const handleScroll = () => {
      const { scrollLeft, scrollWidth, clientWidth } = tableWrapper;
      const isScrolledFromLeft = scrollLeft > 0;
      const isScrolledFromRight = scrollLeft < scrollWidth - clientWidth - 1;

      if (isScrolledFromLeft) {
        tableWrapper.classList.add('show-left-shadow');
        tableWrapper.classList.add('scrolled');
      } else {
        tableWrapper.classList.remove('show-left-shadow');
        tableWrapper.classList.remove('scrolled');
      }

      if (isScrolledFromRight) {
        tableWrapper.classList.add('show-right-shadow');
      } else {
        tableWrapper.classList.remove('show-right-shadow');
      }
    };

    handleScroll();
    tableWrapper.addEventListener('scroll', handleScroll);
    window.addEventListener('resize', handleScroll);

    return () => {
      tableWrapper.removeEventListener('scroll', handleScroll);
      window.removeEventListener('resize', handleScroll);
    };
  }, [allScans]);

  // When using getRecentScans, search is done server-side (Postgres). Otherwise filter client-side.
  const filteredScans = useMemo(() => {
    if (SHOW_TABLE_WITHOUT_SIGN_IN && !isAuthenticated) {
      return allScans; // Server already filtered by debouncedSearch
    }
    if (!searchTerm.trim()) return allScans;
    const term = searchTerm.toLowerCase();
    return allScans.filter(
      (scan) =>
        scan.extension_name?.toLowerCase().includes(term) ||
        scan.extension_id?.toLowerCase().includes(term)
    );
  }, [allScans, searchTerm, isAuthenticated]);

  // Format user count
  const formatUserCount = (count) => {
    if (!count) return "—";
    const num = typeof count === "string" ? parseInt(count.replace(/,/g, ""), 10) : count;
    if (num >= 1000000) return `${(num / 1000000).toFixed(1)}M`;
    if (num >= 1000) return `${(num / 1000).toFixed(1)}K`;
    return num.toString();
  };

  // Format time ago
  const formatTimeAgo = (timestamp) => {
    if (!timestamp) return "—";
    const now = new Date();
    const scanTime = new Date(timestamp);
    const diffMs = now - scanTime;
    const diffMins = Math.floor(diffMs / 60000);
    const diffHours = Math.floor(diffMs / 3600000);
    const diffDays = Math.floor(diffMs / 86400000);

    if (diffMins < 1) return "Just now";
    if (diffMins < 60) return `${diffMins}m ago`;
    if (diffHours < 24) return `${diffHours}h ago`;
    if (diffDays < 7) return `${diffDays}d ago`;
    return scanTime.toLocaleDateString();
  };

  // Handle sorting
  const handleSort = (key) => {
    let direction = "asc";
    if (sortConfig.key === key && sortConfig.direction === "asc") {
      direction = "desc";
    }
    setSortConfig({ key, direction });
  };

  // Sort and paginate data
  const sortedAndPaginatedScans = useMemo(() => {
    let sorted = [...filteredScans];

    if (sortConfig.key) {
      sorted.sort((a, b) => {
        let aVal = a[sortConfig.key];
        let bVal = b[sortConfig.key];
        // For timestamp, use fallback chain (API maps scanned_at→timestamp)
        if (sortConfig.key === "timestamp" || sortConfig.key === "scanned_at") {
          aVal = a.timestamp ?? a.scanned_at ?? a.created_at ?? a.updated_at;
          bVal = b.timestamp ?? b.scanned_at ?? b.created_at ?? b.updated_at;
        }

        if (aVal == null) return 1;
        if (bVal == null) return -1;

        if (sortConfig.key === "extension_name") {
          aVal = (aVal || "").toLowerCase();
          bVal = (bVal || "").toLowerCase();
        } else if (sortConfig.key === "timestamp" || sortConfig.key === "scanned_at") {
          aVal = new Date(aVal).getTime();
          bVal = new Date(bVal).getTime();
        } else if (sortConfig.key === "score" || sortConfig.key === "findings_count") {
          aVal = Number(aVal) || 0;
          bVal = Number(bVal) || 0;
        } else if (typeof aVal === "string") {
          const aNum = parseFloat(aVal);
          const bNum = parseFloat(bVal);
          if (!isNaN(aNum) && !isNaN(bNum)) {
            aVal = aNum;
            bVal = bNum;
          }
        }

        if (aVal < bVal) return sortConfig.direction === "asc" ? -1 : 1;
        if (aVal > bVal) return sortConfig.direction === "asc" ? 1 : -1;
        return 0;
      });
    }

    const startIndex = (currentPage - 1) * rowsPerPage;
    return sorted.slice(startIndex, startIndex + rowsPerPage);
  }, [filteredScans, sortConfig, currentPage, rowsPerPage]);

  const totalPages = Math.ceil(filteredScans.length / rowsPerPage);

  // View existing scan report - no auth required (only scanning new extensions requires login)
  const handleViewReport = (extId) => {
    navigate(`/scan/results/${extId}`);
  };

  const handleCopyLink = async (extId) => {
    const link = `${window.location.origin}/scan/results/${extId}`;
    try {
      await navigator.clipboard.writeText(link);
      setCopiedId(extId);
      setTimeout(() => setCopiedId(null), 2000);
    } catch (err) {
      // console.error("Failed to copy:", err); // prod: no console
    }
  };

  const handleExport = () => {
    const dataToExport = filteredScans.map((scan) => ({
      id: scan.extension_id,
      name: scan.extension_name,
      timestamp: scan.timestamp,
      score: scan.score,
      risk_level: scan.risk_level,
      findings_count: scan.findings_count,
    }));

    const blob = new Blob([JSON.stringify(dataToExport, null, 2)], {
      type: "application/json",
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `extension-shield-history-${new Date().toISOString().split("T")[0]}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const isPublicView = !isAuthenticated;
  const showBlur = isPublicView && !SHOW_TABLE_WITHOUT_SIGN_IN; // No blur when testing without sign-in

  return (
    <>
      <SEOHead
        title="Scan History"
        description="View your Chrome extension scan history and past security reports. Track risk scores, findings, and monitor extension security over time."
        pathname="/scan/history"
        ogType="website"
      />
      <div className="history-page">
        {/* Background Effects */}
        <div className="history-bg">
        <div className="bg-gradient" />
        <div className="bg-grid" />
      </div>

      <div className="history-content">
        {/* Header */}
        <div className="history-header">
          <h1>Scan History</h1>
          <p>Browse and search all scanned extensions</p>
          {!isAuthenticated && (
            <p className="auth-hint" style={{ marginTop: '0.5rem', fontSize: '0.875rem', opacity: 0.8 }}>
              Showing 10 most recent scans. <button onClick={openSignInModal} style={{ background: 'none', border: 'none', color: 'var(--accent-color, #3b82f6)', cursor: 'pointer', textDecoration: 'underline', padding: 0, fontSize: 'inherit' }}>Sign in</button> to scan new extensions (limit: 2 scans/day).
            </p>
          )}
        </div>

        {/* Toolbar */}
        <div className="history-toolbar">
          <div className="toolbar-left">
            <div className="scan-count-badge">
              <span>All Scans</span>
              <span className="count-number">{filteredScans.length}</span>
            </div>
          </div>

          <div className="toolbar-right">
            <div className="search-input-wrapper">
              <svg className="search-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <circle cx="11" cy="11" r="8" />
                <path d="m21 21-4.35-4.35" />
              </svg>
              <input
                type="text"
                className="search-input"
                placeholder="Search extensions (searches Postgres)..."
                value={searchTerm}
                onChange={(e) => {
                  setSearchTerm(e.target.value);
                  setCurrentPage(1);
                }}
              />
            </div>
            <button className="export-btn" onClick={handleExport}>
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
                <polyline points="7,10 12,15 17,10" />
                <line x1="12" y1="15" x2="12" y2="3" />
              </svg>
              Export
            </button>
          </div>
        </div>

        {/* Loading State */}
        {loading && (
          <div className="loading-state">
            <div className="loading-spinner" />
            <span className="loading-text">Loading scan history...</span>
          </div>
        )}

        {/* Extensions Table */}
        {!loading && filteredScans.length > 0 && (
          <div className={`extensions-table-container ${showBlur ? 'blurred-content' : ''}`}>
            <div className="table-wrapper" ref={tableWrapperRef}>
              <table className="extensions-table">
                <thead>
                  <tr>
                    <th className="sortable" onClick={() => handleSort("extension_name")}>
                      <div className="th-content">
                        <svg className="th-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                          <rect x="3" y="3" width="18" height="18" rx="2" />
                          <path d="M12 8v8M8 12h8" />
                        </svg>
                        Extension
                        {sortConfig.key === "extension_name" && (
                          <span className="sort-arrow">{sortConfig.direction === "asc" ? "↑" : "↓"}</span>
                        )}
                      </div>
                    </th>
                    <th className="sortable hide-mobile" onClick={() => handleSort("user_count")}>
                      <div className="th-content">
                        Users
                        {sortConfig.key === "user_count" && (
                          <span className="sort-arrow">{sortConfig.direction === "asc" ? "↑" : "↓"}</span>
                        )}
                      </div>
                    </th>
                    <th className="sortable hide-mobile" onClick={() => handleSort("rating")}>
                      <div className="th-content">
                        Rating
                        {sortConfig.key === "rating" && (
                          <span className="sort-arrow">{sortConfig.direction === "asc" ? "↑" : "↓"}</span>
                        )}
                      </div>
                    </th>
                    <th className="sortable hide-tablet" onClick={() => handleSort("rating_count")}>
                      <div className="th-content">
                        Reviews
                        {sortConfig.key === "rating_count" && (
                          <span className="sort-arrow">{sortConfig.direction === "asc" ? "↑" : "↓"}</span>
                        )}
                      </div>
                    </th>
                    <th className="sortable" onClick={() => handleSort("score")}>
                      <div className="th-content">
                        <svg className="th-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                          <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
                        </svg>
                        Risk
                        {sortConfig.key === "score" && (
                          <span className="sort-arrow">{sortConfig.direction === "asc" ? "↑" : "↓"}</span>
                        )}
                      </div>
                    </th>
                    <th>
                      <div className="th-content">
                        <svg className="th-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                          <path d="M22 12h-4l-3 9L9 3l-3 9H2" />
                        </svg>
                        Signals
                      </div>
                    </th>
                    <th className="sortable" onClick={() => handleSort("findings_count")}>
                      <div className="th-content">
                        <svg className="th-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                          <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
                          <path d="M14 2v6h6" />
                          <line x1="16" y1="13" x2="8" y2="13" />
                          <line x1="16" y1="17" x2="8" y2="17" />
                        </svg>
                        Evidence
                        {sortConfig.key === "findings_count" && (
                          <span className="sort-arrow">{sortConfig.direction === "asc" ? "↑" : "↓"}</span>
                        )}
                      </div>
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {sortedAndPaginatedScans.map((scan, index) => (
                    <tr
                      key={scan.extension_id || index}
                      className={hoveredRow === scan.extension_id ? "row-hovered" : ""}
                      onMouseEnter={() => setHoveredRow(scan.extension_id)}
                      onMouseLeave={() => setHoveredRow(null)}
                    >
                      <td className="extension-cell">
                        <div className="extension-info">
                          <img
                            src={getExtensionIconUrl(scan.extension_id)}
                            alt={scan.extension_name}
                            className="extension-icon"
                            onError={(e) => {
                              e.target.onerror = null;
                              e.target.src = EXTENSION_ICON_PLACEHOLDER;
                            }}
                          />
                          <div className="extension-details">
                            <span className="extension-name">
                              {scan.extension_name || scan.extension_id}
                            </span>
                            <span className="extension-scanned">
                              {formatTimeAgo(scan.timestamp ?? scan.scanned_at ?? scan.created_at ?? scan.updated_at)}
                            </span>
                          </div>
                        </div>
                      </td>
                      <td className="hide-mobile">{formatUserCount(scan.user_count)}</td>
                      <td className="hide-mobile">
                        {scan.rating != null ? (
                          <span className="rating-value">{parseFloat(scan.rating).toFixed(1)}</span>
                        ) : (
                          <span className="no-data">—</span>
                        )}
                      </td>
                      <td className="hide-tablet">
                        {scan.rating_count != null ? (
                          <span>{formatUserCount(scan.rating_count)}</span>
                        ) : (
                          <span className="no-data">—</span>
                        )}
                      </td>
                      <td>
                        <RiskBadge level={scan.risk_level} score={scan.score} />
                      </td>
                      <td className="signals-cell">
                        <div className="signals-container">
                          <SignalChip type="security" signal={scan.signals?.security_signal} />
                          <SignalChip type="privacy" signal={scan.signals?.privacy_signal} />
                          <SignalChip type="governance" signal={scan.signals?.governance_signal} />
                        </div>
                      </td>
                      <td className="evidence-cell">
                        <div className="evidence-container">
                          <span className="findings-count">
                            {scan.findings_count || 0} finding{scan.findings_count !== 1 ? "s" : ""}
                          </span>
                          <button
                            className="view-report-btn"
                            onClick={() => handleViewReport(scan.extension_id)}
                          >
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                              <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z" />
                              <circle cx="12" cy="12" r="3" />
                            </svg>
                            View
                          </button>
                          <button
                            className="copy-link-btn"
                            onClick={() => handleCopyLink(scan.extension_id)}
                            title="Copy share link"
                          >
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                              <path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71" />
                              <path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71" />
                            </svg>
                          </button>
                        </div>
                        {copiedId === scan.extension_id && (
                          <span className="copied-toast">Copied!</span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            {/* Pagination */}
            <div className="table-pagination">
              <div className="pagination-info">
                Showing {(currentPage - 1) * rowsPerPage + 1} to{" "}
                {Math.min(currentPage * rowsPerPage, filteredScans.length)} of {filteredScans.length} rows
              </div>
              <div className="pagination-controls">
                <button
                  className="pagination-btn"
                  onClick={() => setCurrentPage(1)}
                  disabled={currentPage === 1}
                >
                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <path d="M11 17l-5-5 5-5M18 17l-5-5 5-5" />
                  </svg>
                </button>
                <button
                  className="pagination-btn"
                  onClick={() => setCurrentPage((p) => Math.max(1, p - 1))}
                  disabled={currentPage === 1}
                >
                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <path d="M15 18l-6-6 6-6" />
                  </svg>
                </button>
                <button
                  className="pagination-btn"
                  onClick={() => setCurrentPage((p) => Math.min(totalPages, p + 1))}
                  disabled={currentPage === totalPages}
                >
                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <path d="M9 18l6-6-6-6" />
                  </svg>
                </button>
                <button
                  className="pagination-btn"
                  onClick={() => setCurrentPage(totalPages)}
                  disabled={currentPage === totalPages}
                >
                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <path d="M13 17l5-5-5-5M6 17l5-5-5-5" />
                  </svg>
                </button>
              </div>
              <div className="pagination-rows">
                <label>Rows per page:</label>
                <select
                  value={rowsPerPage}
                  onChange={(e) => {
                    setRowsPerPage(Number(e.target.value));
                    setCurrentPage(1);
                  }}
                >
                  <option value={10}>10</option>
                  <option value={25}>25</option>
                  <option value={50}>50</option>
                  <option value={100}>100</option>
                </select>
              </div>
            </div>
          </div>
        )}

        {/* Empty State */}
        {!loading && filteredScans.length === 0 && (
          <div className="empty-state">
            <div className="empty-icon">📭</div>
            <h3>
              {searchTerm
                ? "No matching scans found"
                : isPublicView
                  ? "Sign in to view your scan history"
                  : "No scan history yet"}
            </h3>
            <p>
              {searchTerm
                ? `No scans match "${searchTerm}". Try a different search term.`
                : isPublicView
                  ? "Your saved scans are tied to your account."
                  : "Start by scanning your first Chrome extension."}
            </p>
            {!searchTerm && !isPublicView && (
              <button className="empty-action-btn" onClick={() => navigate("/scan")}>
                <span>⚡</span>
                Start Your First Scan
              </button>
            )}
            {!searchTerm && isPublicView && (
              <button className="empty-action-btn" onClick={openSignInModal}>
                Sign In
              </button>
            )}
          </div>
        )}

        {/* Login Overlay for Blurred Content */}
        {isPublicView && !loading && filteredScans.length > 0 && (
          <div className="login-overlay">
            <div className="login-overlay-content">
              <svg className="lock-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
                <path d="M7 11V7a5 5 0 0 1 10 0v4" />
              </svg>
              <h3>Sign in to view scanned extensions</h3>
              <button className="login-overlay-btn" onClick={openSignInModal}>
                Sign In
              </button>
            </div>
          </div>
        )}
      </div>
      </div>
    </>
  );
};

export default ScanHistoryPage;
