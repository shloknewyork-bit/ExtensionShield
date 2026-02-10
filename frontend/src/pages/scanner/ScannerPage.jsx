import React, { useEffect, useState, useMemo, useRef } from "react";
import { useNavigate, useLocation } from "react-router-dom";
import EnhancedUrlInput from "../../components/EnhancedUrlInput";
import { useScan } from "../../context/ScanContext";
import databaseService from "../../services/databaseService";
import realScanService from "../../services/realScanService";
import {
  getRiskColorClass,
  getSignalColorClass,
} from "../../utils/signalMapper";
import { enrichScans } from "../../utils/scanEnrichment";
import { EXTENSION_ICON_PLACEHOLDER } from "../../utils/constants";
import SEOHead from "../../components/SEOHead";
import "./ScannerPage.scss";

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

// Risk badge component with colored border
const RiskBadge = ({ level, score }) => {
  const colorClass = getRiskColorClass(level);
  
  // Get border color based on score (using new thresholds)
  const getBorderColor = () => {
    if (score === null || score === undefined) return 'rgba(107, 114, 128, 0.3)';
    if (score >= 85) return '#10B981'; // Green
    if (score >= 60) return '#F59E0B'; // Yellow
    return '#EF4444'; // Red
  };

  const getTextColor = () => {
    if (score === null || score === undefined) return '#6B7280';
    if (score >= 85) return '#10B981'; // Green
    if (score >= 60) return '#F59E0B'; // Yellow
    return '#EF4444'; // Red
  };

  return (
    <div 
      className={`risk-badge ${colorClass}`}
      style={{ 
        borderColor: getBorderColor(),
        color: getTextColor()
      }}
    >
      <span className="risk-level">{level || "—"}</span>
    </div>
  );
};

// Row hover actions
const RowActions = ({ scan, onViewReport, onMonitor, onCopyLink, showActions }) => {
  const actionsRef = useRef(null);

  if (!showActions) return null;

  return (
    <div className="row-hover-actions" ref={actionsRef}>
      <button className="hover-action-btn primary" onClick={onViewReport} title="View Report">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z" />
          <circle cx="12" cy="12" r="3" />
        </svg>
        <span>View</span>
      </button>
      <button className="hover-action-btn pro" onClick={onMonitor} title="Monitor (Enterprise)">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <path d="M22 12h-4l-3 9L9 3l-3 9H2" />
        </svg>
        <span>Monitor</span>
        <span className="pro-badge">ENTERPRISE</span>
      </button>
      <button className="hover-action-btn" onClick={onCopyLink} title="Copy Share Link">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71" />
          <path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71" />
        </svg>
      </button>
    </div>
  );
};

const ScannerPage = () => {
  const navigate = useNavigate();
  const location = useLocation();
  const {
    url,
    setUrl,
    isScanning,
    error,
    setError,
    startScan,
    handleFileUpload,
  } = useScan();

  // API base URL - use environment variable or same-origin
  const API_BASE_URL = import.meta.env.VITE_API_URL || "";

  // Helper function to get proper image source from extension data
  const getIconSrc = (extensionId) => {
    // Use the icon from extracted extension via API, fallback to placeholder
    if (extensionId) {
      return `${API_BASE_URL}/api/scan/icon/${extensionId}`;
    }
    return EXTENSION_ICON_PLACEHOLDER;
  };

  const [allScans, setAllScans] = useState([]);
  const [loading, setLoading] = useState(true);
  const [sortConfig, setSortConfig] = useState({ key: "timestamp", direction: "desc" });
  const [currentPage, setCurrentPage] = useState(1);
  const [rowsPerPage, setRowsPerPage] = useState(10);
  const [hoveredRow, setHoveredRow] = useState(null);
  const [copiedId, setCopiedId] = useState(null);
  const tableWrapperRef = useRef(null);

  // Daily deep-scan limit UI state (cached lookups remain available)
  const [deepScanLimit, setDeepScanLimit] = useState(null);
  const [cachedAvailable, setCachedAvailable] = useState(false);

  // Load all scans on mount
  useEffect(() => {
    let isMounted = true;
    const loadScans = async () => {
      setLoading(true);
      
      try {
        // Reduced initial limit for faster load - load 25 initially instead of 100
        // This reduces the number of API calls significantly
        const initialLimit = 25;
        const timeoutPromise = new Promise((_, reject) => 
          setTimeout(() => reject(new Error("Request timeout")), 5000)
        );
        
        const historyPromise = databaseService.getRecentScans(initialLimit);
        const history = await Promise.race([historyPromise, timeoutPromise]);

        console.log(`[ScannerPage] Loaded ${history?.length || 0} scans from API`);

        if (!history || history.length === 0) {
          console.warn("[ScannerPage] No scans found in API response");
          if (isMounted) {
            setAllScans([]);
            setLoading(false);
          }
          return;
        }

        // Always try to use metadata first (skipFullFetch=true) for faster loading
        // This avoids N+1 queries and makes the table render immediately
        // The enrichment function now handles missing scoring_v2 gracefully
        const enrichedScans = await enrichScans(history, { skipFullFetch: true });
        
        if (isMounted) {
          console.log(`[ScannerPage] Enriched ${enrichedScans.length} of ${history.length} scans`);
          
          // Always set the scans, even if some failed to enrich
          // This ensures the table displays if we have any valid scans
          if (enrichedScans.length > 0) {
            setAllScans(enrichedScans);
          } else {
            // If all enrichments failed, try without skipFullFetch as fallback
            console.warn("[ScannerPage] All scans failed enrichment with skipFullFetch, trying full fetch");
            const fallbackScans = await enrichScans(history, { skipFullFetch: false });
            setAllScans(fallbackScans.length > 0 ? fallbackScans : []);
          }
          setLoading(false);
        }
      } catch (error) {
        console.error("Failed to load scans:", error);
        if (isMounted) {
          setAllScans([]);
          setLoading(false);
        }
      }
    };
    loadScans();
    
    // Cleanup function to prevent state updates after unmount
    return () => {
      isMounted = false;
    };
  }, []);

  // Load deep-scan limit status (best-effort)
  useEffect(() => {
    let cancelled = false;
    const loadLimit = async () => {
      try {
        const limit = await realScanService.getDeepScanLimitStatus();
        if (!cancelled) setDeepScanLimit(limit);
      } catch (e) {
        // Ignore - backend may be unavailable in some dev setups
      }
    };
    loadLimit();
    return () => {
      cancelled = true;
    };
  }, []);

  // If backend blocks a deep scan (429), refresh limit status so the button can disable immediately.
  useEffect(() => {
    if (!error || typeof error !== "string") return;
    if (!error.toLowerCase().includes("daily deep-scan limit reached")) return;

    let cancelled = false;
    const refresh = async () => {
      try {
        const limit = await realScanService.getDeepScanLimitStatus();
        if (!cancelled) setDeepScanLimit(limit);
      } catch (e) {
        // ignore
      }
    };
    refresh();
    return () => {
      cancelled = true;
    };
  }, [error]);

  // If limit is reached, check whether this URL maps to an extension with cached results.
  useEffect(() => {
    if (!deepScanLimit || deepScanLimit.remaining > 0) {
      setCachedAvailable(false);
      return;
    }

    const raw = (url || "").trim();
    const extId = realScanService.extractExtensionId(raw);
    if (!raw || !extId) {
      setCachedAvailable(false);
      return;
    }

    let cancelled = false;
    const t = setTimeout(async () => {
      try {
        const cached = await realScanService.hasCachedResults(extId);
        if (!cancelled) setCachedAvailable(Boolean(cached));
      } catch (e) {
        if (!cancelled) setCachedAvailable(false);
      }
    }, 250);

    return () => {
      cancelled = true;
      clearTimeout(t);
    };
  }, [url, deepScanLimit]);

  // Handle scroll shadows for horizontal scrolling on mobile
  useEffect(() => {
    const tableWrapper = tableWrapperRef.current;
    if (!tableWrapper) return;

    const handleScroll = () => {
      const { scrollLeft, scrollWidth, clientWidth } = tableWrapper;
      const isScrolledFromLeft = scrollLeft > 0;
      const isScrolledFromRight = scrollLeft < scrollWidth - clientWidth - 1;

      // Add/remove shadow classes
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

    // Initial check
    handleScroll();

    // Add scroll listener
    tableWrapper.addEventListener('scroll', handleScroll);
    
    // Add resize listener to recalculate on window resize
    window.addEventListener('resize', handleScroll);

    return () => {
      tableWrapper.removeEventListener('scroll', handleScroll);
      window.removeEventListener('resize', handleScroll);
    };
  }, [allScans]);

  // Handle prefilled URL from homepage
  useEffect(() => {
    if (location.state?.prefillUrl) {
      setUrl(location.state.prefillUrl);
      window.history.replaceState({}, document.title);
    }
  }, [location.state, setUrl]);

  const handleScanClick = async () => {
    if (!url.trim()) {
      setError("Please enter a Chrome Web Store URL");
      return;
    }
    await startScan(url);
  };

  const deepScanLimitReached = deepScanLimit && deepScanLimit.remaining <= 0;
  const scanDisabledDueToLimit = Boolean(deepScanLimitReached && !cachedAvailable);
  const scanDisabledTooltip = "Daily deep-scan limit reached. Cached lookups are still unlimited.";
  const scanButtonLabel = scanDisabledDueToLimit
    ? "Daily Limit Reached"
    : deepScanLimitReached && cachedAvailable
      ? "Lookup Report"
      : "Scan Extension";

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
    let sorted = [...allScans];

    if (sortConfig.key) {
      sorted.sort((a, b) => {
        let aVal = a[sortConfig.key];
        let bVal = b[sortConfig.key];

        // Handle null/undefined values
        if (aVal == null) return 1;
        if (bVal == null) return -1;

        // Handle different data types
        if (sortConfig.key === "extension_name") {
          aVal = (aVal || "").toLowerCase();
          bVal = (bVal || "").toLowerCase();
        } else if (sortConfig.key === "timestamp") {
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
  }, [allScans, sortConfig, currentPage, rowsPerPage]);

  const totalPages = Math.ceil(allScans.length / rowsPerPage);

  // Actions
  const handleViewReport = (extId) => {
    navigate(`/scan/results/${extId}`);
  };

  const handleMonitor = (extId) => {
    // Enterprise feature
    navigate("/enterprise");
  };

  const handleCopyLink = async (extId) => {
    const link = `${window.location.origin}/scan/results/${extId}`;
    try {
      await navigator.clipboard.writeText(link);
      setCopiedId(extId);
      setTimeout(() => setCopiedId(null), 2000);
    } catch (err) {
      console.error("Failed to copy:", err);
    }
  };

  const faqSchema = {
    "@context": "https://schema.org",
    "@type": "FAQPage",
    "mainEntity": [
      {
        "@type": "Question",
        "name": "How does Chrome extension security scanning work?",
        "acceptedAnswer": {
          "@type": "Answer",
          "text": "ExtensionShield analyzes Chrome extensions using static code analysis (SAST), permission analysis, and threat intelligence to generate a comprehensive risk score. We check for malware, privacy risks, and compliance issues."
        }
      },
      {
        "@type": "Question",
        "name": "What is an extension risk score?",
        "acceptedAnswer": {
          "@type": "Answer",
          "text": "The extension risk score is a numerical rating (0-100) that indicates the overall security risk of a Chrome extension. It's calculated based on code analysis, permission requests, and threat intelligence signals."
        }
      },
      {
        "@type": "Question",
        "name": "What permissions should I be concerned about?",
        "acceptedAnswer": {
          "@type": "Answer",
          "text": "Be cautious of extensions requesting broad permissions like 'Read and change all your data on all websites', 'Access your browsing history', or 'Manage your downloads'. Learn more about extension permissions in our glossary."
        }
      },
      {
        "@type": "Question",
        "name": "Can I scan extensions before installing them?",
        "acceptedAnswer": {
          "@type": "Answer",
          "text": "Yes! ExtensionShield allows you to scan any Chrome extension from the Chrome Web Store before installing it. Simply paste the extension URL or Chrome Web Store ID to get an instant security analysis."
        }
      },
      {
        "@type": "Question",
        "name": "How accurate is the extension security scanner?",
        "acceptedAnswer": {
          "@type": "Answer",
          "text": "ExtensionShield uses multiple security analysis techniques including static code analysis, permission analysis, and threat intelligence from VirusTotal. Our methodology is transparent and documented in our research section."
        }
      }
    ]
  };

  const softwareAppSchema = {
    "@context": "https://schema.org",
    "@type": "SoftwareApplication",
    "name": "ExtensionShield",
    "applicationCategory": "SecurityApplication",
    "operatingSystem": "Web",
    "offers": {
      "@type": "Offer",
      "price": "0",
      "priceCurrency": "USD"
    },
    "description": "Free Chrome extension security scanner that analyzes extensions for malware, privacy risks, and compliance issues.",
    "url": "https://extensionshield.com/scan"
  };

  return (
    <>
      <SEOHead
        title="Scan Chrome Extension Security & Risk Score"
        description="Scan any Chrome extension for security vulnerabilities, privacy risks, and compliance issues. Get instant risk scores and detailed security analysis before installing."
        pathname="/scan"
        ogType="website"
        schema={[faqSchema, softwareAppSchema]}
      />
      <div className="scanner-page">
        <section className="scanner-hero">
        {/* Background */}
        <div className="scanner-bg">
          <div className="bg-gradient" />
          <div className="bg-grid" />
        </div>

        {/* Main Content */}
        <div className="scanner-content">
          {/* Header */}
          <div className="scanner-header">
            <h1>Extension Scanner</h1>
            <p>Analyze any Chrome extension for security threats and compliance issues</p>
          </div>

          {/* Scan Input Box */}
          <div className="scan-input-wrapper">
            <EnhancedUrlInput
              value={url}
              onChange={setUrl}
              onScan={handleScanClick}
              onFileUpload={handleFileUpload}
              isScanning={isScanning}
              scanDisabled={scanDisabledDueToLimit}
              scanDisabledTooltip={scanDisabledTooltip}
              scanButtonLabel={scanButtonLabel}
            />
          </div>

          {scanDisabledDueToLimit && (
            <div className="deep-scan-limit-banner">
              Daily deep-scan limit reached. Cached lookups are still unlimited.
            </div>
          )}

          {/* Error Message */}
          {error && !error.includes("✅") && !error.includes("🔄") && (
            <div className="error-message">
              <span>{error}</span>
              <button onClick={() => setError(null)}>✕</button>
            </div>
          )}
        </div>

        {/* Extensions Table */}
        <div className="extensions-table-container">
          <div className="table-header-section">
            {loading && <div className="loading-indicator">Loading...</div>}
          </div>

          {!loading && allScans.length > 0 && (
            <>
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
                              src={getIconSrc(scan.extension_id)}
                              alt={scan.extension_name}
                              className="extension-icon"
                              onError={(e) => {
                                // On error, fallback to placeholder
                                e.target.onerror = null;
                                e.target.src = EXTENSION_ICON_PLACEHOLDER;
                              }}
                            />
                            <div className="extension-details">
                              <span className="extension-name">
                                {scan.extension_name || scan.extension_id}
                              </span>
                              <span className="extension-scanned">
                                {formatTimeAgo(scan.timestamp)}
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
                          </div>
                          <RowActions
                            scan={scan}
                            showActions={hoveredRow === scan.extension_id}
                            onViewReport={() => handleViewReport(scan.extension_id)}
                            onMonitor={() => handleMonitor(scan.extension_id)}
                            onCopyLink={() => handleCopyLink(scan.extension_id)}
                          />
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
                  {Math.min(currentPage * rowsPerPage, allScans.length)} of {allScans.length} rows
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
            </>
          )}

          {!loading && allScans.length === 0 && (
            <div className="empty-state">
              <div className="empty-icon">🛡️</div>
              <h3>No extensions scanned yet</h3>
              <p>Start by scanning your first Chrome extension above</p>
            </div>
          )}
        </div>
      </section>
      </div>
    </>
  );
};

export default ScannerPage;
