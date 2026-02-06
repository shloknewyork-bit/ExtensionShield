import React, { useEffect, useState, useRef } from "react";
import { useParams, useNavigate, Link } from "react-router-dom";
import { Button } from "../../components/ui/button";
import { Badge } from "../../components/ui/badge";
import {
  RiskDial,
  ReportScoreCard,
  KeyFindings,
  FactorBars,
  EvidenceDrawer,
  PermissionsPanel,
  ExecutiveSummary,
  WhyThisScore,
} from "../../components/report";
import FileViewerModal from "../../components/FileViewerModal";
import StatusMessage from "../../components/StatusMessage";
import { useScan } from "../../context/ScanContext";
import realScanService from "../../services/realScanService";
import { normalizeScanResultSafe, validateEvidenceIntegrity } from "../../utils/normalizeScanResult";
import "./ScanResultsPageV2.scss";

/**
 * ScanResultsPageV2 - Redesigned results dashboard
 * Uses ReportViewModel from normalizeScanResultSafe() - NO fake data
 */
const ScanResultsPageV2 = () => {
  const { scanId } = useParams();
  const navigate = useNavigate();
  const {
    scanResults,
    error,
    setError,
    loadResultsById,
    currentExtensionId,
  } = useScan();

  const [isLoading, setIsLoading] = useState(false);
  const [rawData, setRawData] = useState(null);
  const [viewModel, setViewModel] = useState(null);
  const [normalizationError, setNormalizationError] = useState(null);
  const [showHeroIcon, setShowHeroIcon] = useState(true);
  const [fileViewerModal, setFileViewerModal] = useState({
    isOpen: false,
    file: null,
  });
  
  // Evidence drawer state
  const [evidenceDrawer, setEvidenceDrawer] = useState({
    open: false,
    evidenceIds: [],
  });

  // Track which scanId we've loaded to prevent double loading
  const loadedScanIdRef = useRef(null);
  const isLoadingRef = useRef(false);

  // Reset loaded ref when scanId changes
  useEffect(() => {
    if (loadedScanIdRef.current !== scanId) {
      loadedScanIdRef.current = null;
      isLoadingRef.current = false;
    }
  }, [scanId]);

  // Load results and normalize
  useEffect(() => {
    const loadResults = async () => {
      // Prevent double loading: check if we're already loading or if we've already loaded this scanId
      if (isLoadingRef.current || loadedScanIdRef.current === scanId) {
        return;
      }

      // Only load if we don't have results or if the current extension ID doesn't match
      if (!scanResults || currentExtensionId !== scanId) {
        isLoadingRef.current = true;
        setIsLoading(true);
        try {
          await loadResultsById(scanId);
          loadedScanIdRef.current = scanId;
        } finally {
          isLoadingRef.current = false;
          setIsLoading(false);
        }
      } else {
        // We already have the correct results, just mark as loaded
        loadedScanIdRef.current = scanId;
      }
    };
    loadResults();
    // Only depend on scanId - remove scanResults and currentExtensionId to prevent circular updates
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [scanId, loadResultsById]);

  // Redirect to canonical URL if we have extensionId and buildHash
  useEffect(() => {
    if (scanResults && scanResults.extension_id && scanResults.build_hash) {
      const canonicalUrl = `/extension/${scanResults.extension_id}/version/${scanResults.build_hash}`;
      // Only redirect if we're not already on a canonical URL
      if (!window.location.pathname.includes('/extension/')) {
        navigate(canonicalUrl, { replace: true });
      }
    }
  }, [scanResults, navigate]);

  // Normalize scan results when they change
  useEffect(() => {
    if (scanResults) {
      setRawData(scanResults);
      
      // Use safe normalizer - never throws
      const vm = normalizeScanResultSafe(scanResults);
      setViewModel(vm);
      
      if (!vm) {
        setNormalizationError("Failed to normalize scan result data");
        console.error("[ScanResultsPageV2] normalizeScanResultSafe returned null");
      } else {
        setNormalizationError(null);
        
        // Validate evidence integrity
        const validation = validateEvidenceIntegrity(vm);
        if (!validation.valid) {
          validation.warnings.forEach(warning => {
            console.warn(`[ScanResultsPageV2] Evidence warning: ${warning}`);
          });
        }
      }
    }
  }, [scanResults]);

  const handleViewFile = (file) => {
    setFileViewerModal({ isOpen: true, file });
  };

  const getFileContent = async (extensionId, filePath) => {
    return await realScanService.getFileContent(extensionId, filePath);
  };

  const openEvidenceDrawer = (evidenceIds) => {
    if (evidenceIds && evidenceIds.length > 0) {
      setEvidenceDrawer({ open: true, evidenceIds });
    }
  };

  const closeEvidenceDrawer = () => {
    setEvidenceDrawer({ open: false, evidenceIds: [] });
  };

  const baseURL = import.meta.env.VITE_API_URL || "";
  const extensionIdForIcon = viewModel?.meta?.extensionId || scanId;
  // Construct icon URL - use full URL if baseURL is set, otherwise use relative path
  const heroIconUrl =
    viewModel?.meta?.iconUrl ||
    (extensionIdForIcon 
      ? (baseURL 
          ? `${baseURL}/api/scan/icon/${extensionIdForIcon}` 
          : `/api/scan/icon/${extensionIdForIcon}`)
      : null);

  // Reset icon visibility when viewing a different extension
  useEffect(() => {
    setShowHeroIcon(true);
  }, [extensionIdForIcon]);

  // Loading state
  if (isLoading) {
    return (
      <div className="results-v2">
        <div className="results-v2-loading">
          <div className="loading-pulse" />
          <h2>Analyzing Extension</h2>
          <p>Running security scans...</p>
          <code>{scanId}</code>
        </div>
      </div>
    );
  }

  // No results
  if (!scanResults && !isLoading) {
    return (
      <div className="results-v2">
        <div className="results-v2-empty">
          <div className="empty-icon">📋</div>
          <h2>No Results Found</h2>
          <p>This extension hasn't been scanned yet.</p>
          <div className="empty-actions">
            <Button onClick={() => navigate("/scanner")} variant="default">
              Start Scan
            </Button>
          </div>
        </div>
      </div>
    );
  }

  // Normalization failed - show error state
  if (!viewModel && normalizationError) {
    return (
      <div className="results-v2">
        <nav className="results-v2-nav">
          <Link to="/scanner" className="nav-back">← Back</Link>
        </nav>
        <div className="results-v2-error">
          <div className="error-icon">⚠️</div>
          <h2>Report Data Unavailable</h2>
          <p>{normalizationError}</p>
          <div className="error-extension-id">
            <span>Extension ID:</span>
            <code>{scanId}</code>
          </div>
          {process.env.NODE_ENV === 'development' && rawData && (
            <details className="error-raw-data">
              <summary>Raw Data (Dev Only)</summary>
              <pre>{JSON.stringify(rawData, null, 2)}</pre>
            </details>
          )}
          <div className="error-actions">
            <Button onClick={() => navigate("/scanner")}>Back to Scanner</Button>
            <Button variant="outline" onClick={() => window.location.reload()}>
              Retry
            </Button>
          </div>
        </div>
      </div>
    );
  }

  // Extract data from viewModel
  const { meta, scores, factorsByLayer, keyFindings, permissions, evidenceIndex } = viewModel || {};

  return (
    <div className="results-v2">
      {/* Navigation Bar */}
      <nav className="results-v2-nav">
        <Link to="/scanner" className="nav-back">
          ← Back
        </Link>
        <div className="nav-actions">
          <Button
            variant="ghost"
            size="sm"
            onClick={() => {
              const baseURL = import.meta.env.VITE_API_URL || "";
              window.open(`${baseURL}/api/scan/report/${scanId}`, '_blank');
            }}
          >
            Export PDF
          </Button>
          <Button
            variant="default"
            size="sm"
            onClick={() => navigate("/scanner")}
          >
            New Scan
          </Button>
        </div>
      </nav>

      {/* Hero Section - Risk Dial Centered */}
      <header className="results-v2-hero">
        {/* Extension Name with Icon - Above Dial */}
        <div className="hero-extension-info">
          <div className="hero-header">
            {showHeroIcon && heroIconUrl && (
              <img
                src={heroIconUrl}
                alt={`${meta?.name || "Extension"} icon`}
                className="hero-icon"
                loading="lazy"
                onError={(e) => {
                  // Try to fallback to placeholder or hide icon
                  e.target.onerror = null;
                  setShowHeroIcon(false);
                }}
              />
            )}
            <h1 className="hero-title">{meta?.name || "Extension Analysis"}</h1>
          </div>
        </div>

        {/* Risk Dial - Centered Focal Point */}
        <div className="hero-dial-container">
          <RiskDial 
            score={scores?.overall?.score ?? scores?.security?.score ?? 0} 
            band={scores?.overall?.band || scores?.security?.band || 'NA'}
            label="RISK"
            decision={scores?.decision}
            size={320}
          />
        </div>

        {/* Extension Metadata - Below Dial */}
        <div className="hero-metadata">
          {meta?.users && (
            <span className="meta-item">
              <span className="meta-icon">👥</span>
              {meta.users.toLocaleString()} users
            </span>
          )}
          {meta?.rating && (
            <span className="meta-item">
              <span className="meta-icon">⭐</span>
              {meta.rating.toFixed(1)} rating
            </span>
          )}
          {scanResults?.developer && (
            <span className="meta-item">
              <span className="meta-icon">👤</span>
              {scanResults.developer}
            </span>
          )}
          {meta?.scanTimestamp && (
            <span className="meta-item meta-item-muted">
              Scanned {new Date(meta.scanTimestamp).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' })}
            </span>
          )}
        </div>
      </header>

      {/* Status Messages */}
      {error && (
        <StatusMessage
          type="error"
          message={error}
          onDismiss={() => setError("")}
        />
      )}

      {/* Main Content */}
      <main className="results-v2-main">
        {/* Executive Summary - First, sets context */}
        {(scanResults?.executiveSummary || (scores?.reasons && scores.reasons.length > 0)) && (
          <ExecutiveSummary 
            summary={scanResults?.executiveSummary || null}
            reasons={scores?.reasons || []}
          />
        )}

        {/* Score Cards Row - Equal Prominence */}
        <section className="scores-section">
          <ReportScoreCard 
            title="Security"
            score={scores?.security?.score}
            band={scores?.security?.band || 'NA'}
            confidence={scores?.security?.confidence}
            contributors={factorsByLayer?.security?.slice(0, 2) || []}
          />
          <ReportScoreCard 
            title="Privacy"
            score={scores?.privacy?.score}
            band={scores?.privacy?.band || 'NA'}
            confidence={scores?.privacy?.confidence}
            contributors={factorsByLayer?.privacy?.slice(0, 2) || []}
          />
          <ReportScoreCard 
            title="Governance"
            score={scores?.governance?.score}
            band={scores?.governance?.band || 'NA'}
            confidence={scores?.governance?.confidence}
            contributors={factorsByLayer?.governance?.slice(0, 2) || []}
          />
        </section>

        {/* Why This Score - Top Contributors Explanation */}
        <WhyThisScore 
          scores={scores}
          factorsByLayer={factorsByLayer}
          onViewEvidence={openEvidenceDrawer}
        />

        {/* Key Findings - Issues that matter */}
        {keyFindings && keyFindings.length > 0 && (
          <KeyFindings 
            findings={keyFindings}
            onViewEvidence={openEvidenceDrawer}
          />
        )}

        {/* Detailed Analysis - Full Width */}
        {/* Security Analysis */}
        {factorsByLayer?.security && factorsByLayer.security.length > 0 && (
          <section className="analysis-section">
            <FactorBars 
              title="Security Analysis"
              icon="🛡️"
              factors={factorsByLayer.security}
              onViewEvidence={openEvidenceDrawer}
            />
          </section>
        )}

        {/* Privacy Analysis - Equal Treatment */}
        {factorsByLayer?.privacy && factorsByLayer.privacy.length > 0 && (
          <section className="analysis-section">
            <FactorBars 
              title="Privacy Analysis"
              icon="🔒"
              factors={factorsByLayer.privacy}
              onViewEvidence={openEvidenceDrawer}
            />
          </section>
        )}

        {/* Governance Analysis - Equal Treatment */}
        {factorsByLayer?.governance && factorsByLayer.governance.length > 0 && (
          <section className="analysis-section">
            <FactorBars 
              title="Governance Analysis"
              icon="📋"
              factors={factorsByLayer.governance}
              onViewEvidence={openEvidenceDrawer}
            />
          </section>
        )}

        {/* Permissions */}
        {permissions && Object.keys(permissions).length > 0 && (
          <section className="analysis-section">
            <PermissionsPanel permissions={permissions} />
          </section>
        )}
      </main>

      {/* Evidence Drawer - Global, mounted once */}
      <EvidenceDrawer 
        open={evidenceDrawer.open}
        evidenceIds={evidenceDrawer.evidenceIds}
        evidenceIndex={evidenceIndex || {}}
        onClose={closeEvidenceDrawer}
      />

      {/* File Viewer Modal */}
      <FileViewerModal
        isOpen={fileViewerModal.isOpen}
        onClose={() => setFileViewerModal({ isOpen: false, file: null })}
        file={fileViewerModal.file}
        extensionId={meta?.extensionId || scanId}
        onGetFileContent={getFileContent}
      />
    </div>
  );
};

export default ScanResultsPageV2;
