import React, { useEffect, useRef, useState, useCallback } from "react";
import { useParams, useNavigate, useLocation, Link } from "react-router-dom";
import { Button } from "../../components/ui/button";
import RocketGame from "../../components/RocketGame";
import { useScan } from "../../context/ScanContext";
import { EXTENSION_ICON_PLACEHOLDER, getExtensionIconUrl } from "../../utils/constants";
import realScanService from "../../services/realScanService";
import { getScanResultsRoute } from "../../utils/slug";
import ScanHUD from "../../components/ScanHUD";
import SEOHead from "../../components/SEOHead";
import { normalizeExtensionId } from "../../utils/extensionId";
import { logger } from "../../utils/logger";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "../../components/ui/dialog";
import "./ScanProgressPage.scss";

// Error Boundary for RocketGame
class RocketGameErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error) {
    return { hasError: true, error };
  }

  componentDidCatch(error, errorInfo) {
    logger.error("RocketGame error:", error, errorInfo);
  }

  render() {
    if (this.state.hasError) {
      return (
        <div style={{
          position: 'fixed',
          inset: 0,
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          background: 'var(--theme-bg-primary)',
          color: 'var(--theme-text-primary)',
          flexDirection: 'column',
          gap: '1rem',
          zIndex: 1000
        }}>
          <div style={{ fontSize: '3rem' }}>⚠️</div>
          <h2 style={{ fontSize: '1.5rem', margin: 0 }}>Game Failed to Load</h2>
          <p style={{ color: 'var(--theme-text-secondary)', margin: 0 }}>
            The game encountered an error, but scan polling continues.
          </p>
        </div>
      );
    }

    return this.props.children;
  }
}

const RocketGameWrapper = ({ onStatsUpdate }) => {
  useEffect(() => {
    if (import.meta.env.DEV) {
      logger.log("[ScanProgressPage] RocketGame mounted");
      return () => logger.log("[ScanProgressPage] RocketGame unmounting");
    }
  }, []);

  return <RocketGame isActive onStatsUpdate={onStatsUpdate} />;
};

const ScanProgressPage = () => {
  const params = useParams();
  const navigate = useNavigate();
  const location = useLocation();
  
  // Read scanId from any possible param key (scanId, extensionId, id)
  const rawScanId = params.scanId || params.extensionId || params.id || '';
  
  // Normalize the extension ID - extract exactly 32 chars (a-p) and remove trailing characters
  const scanId = normalizeExtensionId(rawScanId);
  
  // Dev-only logging
  useEffect(() => {
    if (import.meta.env.DEV) {
      logger.log("[ScanProgressPage] Params:", params);
      logger.log("[ScanProgressPage] Raw scanId:", rawScanId);
      logger.log("[ScanProgressPage] Normalized scanId:", scanId);
    }
  }, [params, rawScanId, scanId]);
  const {
    isScanning,
    scanStage,
    error,
    setError,
    scanResults,
    setScanResults,
    setCurrentExtensionId,
    currentExtensionId,
  } = useScan();
  
  const [extensionLogo, setExtensionLogo] = useState(EXTENSION_ICON_PLACEHOLDER);
  const [extensionName, setExtensionName] = useState(null);
  const [scanComplete, setScanComplete] = useState(false);
  const [alreadyScanned, setAlreadyScanned] = useState(false);
  // Initialize userExited to false - always start with game visible when scanId exists
  const [userExited, setUserExited] = useState(false);
  const [showErrorModal, setShowErrorModal] = useState(false);
  const [showCompletionModal, setShowCompletionModal] = useState(false);
  const [errorMessage, setErrorMessage] = useState("");
  const [gameStats, setGameStats] = useState({ score: 0, best: 0, time: 0 });
  const [gameOver, setGameOver] = useState(false);
  const [scanProgress, setScanProgress] = useState(0);
  const [isMobile, setIsMobile] = useState(false);
  const [userChoseKeepPlaying, setUserChoseKeepPlaying] = useState(false);
  const completionShownRef = useRef(false);
  // Tracks whether any in-progress state was seen before completion.
  // If the first poll returns scanned=true, the extension was already scanned.
  const hasSeenInProgressRef = useRef(false);
  
  // Detect mobile
  useEffect(() => {
    const checkMobile = () => {
      setIsMobile(window.innerWidth <= 768);
    };
    checkMobile();
    window.addEventListener("resize", checkMobile);
    return () => window.removeEventListener("resize", checkMobile);
  }, []);

  // Fetch extension logo and name with error handling
  useEffect(() => {
    if (!scanId) return;
    let cancelled = false;
    
    const iconUrl = getExtensionIconUrl(scanId);
    
    // Try to load the icon with error handling
    try {
      const img = new Image();
      img.onload = () => {
        if (!cancelled) setExtensionLogo(iconUrl);
      };
      img.onerror = () => {
        if (!cancelled) setExtensionLogo(EXTENSION_ICON_PLACEHOLDER);
      };
      img.src = iconUrl;
    } catch (err) {
      // Silently fail - use placeholder
      if (!cancelled) setExtensionLogo(EXTENSION_ICON_PLACEHOLDER);
    }

    // Try to fetch extension name from scan results
    const fetchExtensionInfo = async () => {
      try {
        const results = await realScanService.getRealScanResults(scanId);
        if (cancelled) return;
        if (results?.extension_name) {
          setExtensionName(results.extension_name);
        } else if (results?.metadata?.title) {
          setExtensionName(results.metadata.title);
        }
      } catch (e) {
        // Silently fail - results might not exist yet (scan still running)
      }
    };
    fetchExtensionInfo();

    return () => { cancelled = true; };
  }, [scanId]);

  // Calculate scan progress based on stage
  useEffect(() => {
    if (!scanStage) return;
    
    const stageProgressMap = {
      extracting: 14,
      security_scan: 28,
      building_evidence: 42,
      applying_rules: 71,
      generating_report: 100,
    };
    
    setScanProgress(stageProgressMap[scanStage] || 0);
  }, [scanStage]);

  // Poll scan status while on this page (supports direct refresh/back navigation)
  // Stops polling once scan completes or fails to save server resources.
  // Also detects "already scanned" extensions (first poll returns scanned=true
  // before any in-progress state was observed).
  useEffect(() => {
    if (!scanId) return;

    let cancelled = false;
    let intervalId = null;

    const checkStatus = async () => {
      if (cancelled) return;

      try {
        const status = await realScanService.checkScanStatus(scanId);
        if (cancelled) return;

        // Check for API key errors (401)
        if (status.error_code === 401 || (status.status === "failed" && (status.error?.includes("API key") || status.error?.includes("Connection is down")))) {
          setError("Connection is down try back in a while");
          if (intervalId) { clearInterval(intervalId); intervalId = null; }
          return;
        }
        if (status.status === "failed") {
          if (status.error) setError(status.error);
          if (intervalId) { clearInterval(intervalId); intervalId = null; }
          return;
        }

        // Track whether we've ever seen an in-progress (non-complete) state.
        if (!status.scanned) {
          hasSeenInProgressRef.current = true;
        }

        if (status.scanned) {
          // Stop polling immediately on completion
          if (intervalId) { clearInterval(intervalId); intervalId = null; }

          // Detect "already scanned": completed on first poll, never saw in-progress
          const wasAlreadyScanned = !hasSeenInProgressRef.current;
          if (wasAlreadyScanned) {
            setAlreadyScanned(true);
            setScanProgress(100);
          }

          setScanComplete(true);
          if (!completionShownRef.current) {
            completionShownRef.current = true;
            setShowCompletionModal(true);
          }

          // Best-effort: fetch results and set current extension so results page has cache (no flash).
          try {
            const results = await realScanService.getRealScanResults(scanId);
            if (!cancelled && results) {
              setScanResults(results);
              setCurrentExtensionId(scanId);
            }
          } catch (_e) {
            // Results might not be ready yet — no further polling needed.
          }
        }
      } catch (e) {
        if (cancelled) return;
        if (e.message?.includes("401") || e.message?.includes("API key") || e.message?.includes("Connection is down")) {
          setError("Connection is down try back in a while");
          if (intervalId) { clearInterval(intervalId); intervalId = null; }
        }
      }
    };

    // Kick once immediately and then poll
    checkStatus();
    intervalId = setInterval(checkStatus, 2500);

    return () => {
      cancelled = true;
      if (intervalId) clearInterval(intervalId);
    };
  }, [scanId, setError, setScanResults, setCurrentExtensionId]);

  // Reset state when scanId changes or on mount
  // This ensures that when navigating to a new scan, the game always shows immediately
  useEffect(() => {
    if (scanId) {
      setUserExited(false);
      setScanComplete(false);
      setAlreadyScanned(false);
      setUserChoseKeepPlaying(false);
      completionShownRef.current = false;
      hasSeenInProgressRef.current = false;
    }
  }, [scanId]);
  
  // Stable callback for game stats — avoids re-creating the function on every render
  // which would cause the RocketGame effect to restart the RAF loop.
  const handleStatsUpdate = useCallback((stats) => {
    setGameStats(stats);
    if (stats.gameOver !== undefined) {
      setGameOver(stats.gameOver);
    }
  }, []);

  // Always show game when scanId exists in URL (unless user explicitly exited)
  // This is the primary condition - if scanId exists, show the game
  const shouldShowGame = scanId ? !userExited : false;

  // Handle errors with modal (don't close game)
  useEffect(() => {
    if (error && shouldShowGame) {
      // Check for API key errors (401) - show user-friendly message
      let displayError = error;
      if (error.includes("API key") || error.includes("Invalid API key") || error.includes("Authentication") || error.includes("401") || error.includes("sk-proj")) {
        displayError = "Connection is down try back in a while";
      }
      setErrorMessage(displayError);
      setShowErrorModal(true);
      // Don't clear error - let user dismiss it
    }
  }, [error, shouldShowGame]);

  // Catch any unhandled errors (parsing, network, etc.)
  useEffect(() => {
    const handleError = (event) => {
      if (shouldShowGame) {
        let errorMsg = "Something went wrong";
        
        // Handle different error types
        if (event.error) {
          errorMsg = event.error?.message || String(event.error);
        } else if (event.message) {
          errorMsg = event.message;
        }
        
        // Check for common error patterns
        if (errorMsg.includes("401") || errorMsg.includes("API key") || errorMsg.includes("Invalid API key") || errorMsg.includes("Connection is down")) {
          errorMsg = "Connection is down try back in a while";
        } else if (errorMsg.includes("quota") || errorMsg.includes("token_quota") || (errorMsg.includes("403") && errorMsg.includes("token"))) {
          errorMsg = "Scan analysis quota exceeded. Check your provider limits or try again later.";
        } else if (errorMsg.includes("Connection refused") || errorMsg.includes("Errno 61") || errorMsg.includes("LLM service")) {
          errorMsg = "Scan analysis service unavailable. Check your provider configuration.";
        } else if (errorMsg.includes("JSON") || errorMsg.includes("parse")) {
          errorMsg = "Failed to parse server response. The scan may still be running.";
        } else if (errorMsg.includes("fetch") || errorMsg.includes("network") || errorMsg.includes("Failed to fetch")) {
          errorMsg = "Network error occurred. Check your connection and try again.";
        }
        
        setErrorMessage(errorMsg);
        setShowErrorModal(true);
        event.preventDefault();
      }
    };

    const handleUnhandledRejection = (event) => {
      if (shouldShowGame) {
        let errorMsg = "Something went wrong";
        
        if (event.reason) {
          if (typeof event.reason === "string") {
            errorMsg = event.reason;
          } else if (event.reason?.message) {
            errorMsg = event.reason.message;
          } else {
            errorMsg = String(event.reason);
          }
        }
        
        // Check for API key errors first
        if (errorMsg.includes("401") || errorMsg.includes("API key") || errorMsg.includes("Invalid API key") || errorMsg.includes("Authentication") || errorMsg.includes("sk-proj") || errorMsg.includes("Connection is down")) {
          errorMsg = "Connection is down try back in a while";
        } else if (errorMsg.includes("quota") || errorMsg.includes("token_quota") || (errorMsg.includes("403") && errorMsg.includes("token"))) {
          errorMsg = "Scan analysis quota exceeded. Check your provider limits or try again later.";
        } else if (errorMsg.includes("Connection refused") || errorMsg.includes("Errno 61") || errorMsg.includes("LLM service")) {
          errorMsg = "Scan analysis service unavailable. Check your provider configuration.";
        } else if (errorMsg.includes("JSON") || errorMsg.includes("parse")) {
          errorMsg = "Failed to parse server response. The scan may still be running.";
        } else if (errorMsg.includes("fetch") || errorMsg.includes("network") || errorMsg.includes("Failed to fetch")) {
          errorMsg = "Network error occurred. Check your connection and try again.";
        }
        
        setErrorMessage(errorMsg);
        setShowErrorModal(true);
        event.preventDefault();
      }
    };

    window.addEventListener("error", handleError);
    window.addEventListener("unhandledrejection", handleUnhandledRejection);

    return () => {
      window.removeEventListener("error", handleError);
      window.removeEventListener("unhandledrejection", handleUnhandledRejection);
    };
  }, [shouldShowGame]);

  const handleViewResults = useCallback(() => {
    setUserExited(true);
    setShowCompletionModal(false);
    const extId = scanResults?.extension_id || scanId;
    const extName = scanResults?.extension_name;
    const route = getScanResultsRoute(extId, extName);
    if (route) navigate(route, { replace: true });
  }, [scanResults?.extension_id, scanResults?.extension_name, scanId, navigate]);

  const handleDismissError = useCallback(() => {
    setShowErrorModal(false);
    setError(null);
    setErrorMessage("");
  }, [setError]);

  const handleContinuePlaying = useCallback(() => {
    setShowCompletionModal(false);
    setUserChoseKeepPlaying(true);
  }, []);

  // Always render something - never show blank page
  // Show error if normalized ID is empty (invalid format or missing)
  if (!scanId) {
    if (import.meta.env.DEV) {
      logger.warn("[ScanProgressPage] No valid scanId found. Raw params:", params);
    }
    return (
      <div className="scan-progress-page">
        <div className="progress-container">
          <div className="no-scan-state">
            <div className="no-scan-icon">⚠️</div>
            <h2>Invalid Extension ID</h2>
            <p>
              {rawScanId 
                ? `The extension ID "${rawScanId}" is not in a valid format. Extension IDs must be exactly 32 characters (a-p).`
                : "No extension ID provided in the URL."}
            </p>
            <Button onClick={() => navigate("/scan")} variant="default">
              Go to Scanner
            </Button>
          </div>
        </div>
      </div>
    );
  }

  // When scanId exists, always show the game screen (unless user explicitly exited)
  // This ensures the game shows immediately when navigating to this route
  // Use the same logic as shouldShowGame for consistency
  const showGameScreen = shouldShowGame;

  return (
    <>
      <SEOHead
        title="Scan in progress"
        description="Extension scan in progress."
        pathname={location.pathname}
        noindex
      />
      <div className="scan-progress-page">
      {showGameScreen ? (
        <>
          {/* Retro Style Header Overlay */}
          <div className="retro-header-overlay">
            <h1 className="retro-title">
              <span className="retro-text">
                {scanComplete
                  ? (alreadyScanned
                      ? "RESULTS READY — Previously Scanned"
                      : "SCAN COMPLETE")
                  : "Scan in progress — game mode."}
              </span>
            </h1>
            {/* Exit button appears when scan is complete, but hidden if user chose to keep playing */}
            {scanComplete && !userChoseKeepPlaying && (
              <div className="retro-exit-container">
                <Button
                  onClick={handleViewResults}
                  className="retro-exit-button"
                  variant="default"
                  size="lg"
                >
                  View Results
                </Button>
              </div>
            )}
          </div>

          {/* Full Viewport Game Container */}
          <div className="game-container-fullscreen">
            <RocketGameErrorBoundary>
              <RocketGameWrapper onStatsUpdate={handleStatsUpdate} />
            </RocketGameErrorBoundary>
          </div>

          {/* Scan HUD */}
          <ScanHUD
            extensionIcon={extensionLogo}
            extensionName={extensionName || `Extension ${scanId?.substring(0, 8)}...`}
            extensionId={scanId}
            scanStage={scanStage}
            scanProgress={alreadyScanned ? 100 : scanProgress}
            gameStats={gameStats}
            onViewFindings={handleViewResults}
            isMobile={isMobile}
            gameOver={gameOver}
            scanComplete={scanComplete}
            alreadyScanned={alreadyScanned}
          />

          {/* Error Modal - doesn't close game */}
          <Dialog open={showErrorModal} onOpenChange={setShowErrorModal}>
            <DialogContent className="error-modal-content">
              <DialogHeader>
                <DialogTitle className="error-modal-title">
                  Something Went Wrong
                </DialogTitle>
                <DialogDescription className="error-modal-description">
                  {errorMessage || "An error occurred, but you can continue playing the game."}
                </DialogDescription>
              </DialogHeader>
              <DialogFooter>
                <Button onClick={handleDismissError} variant="default">
                  Continue Playing
                </Button>
                <Button onClick={() => navigate("/scan")} variant="outline">
                  Go to Scanner
                </Button>
              </DialogFooter>
            </DialogContent>
          </Dialog>

          {/* Completion Modal */}
          <Dialog open={showCompletionModal} onOpenChange={setShowCompletionModal}>
            <DialogContent className="completion-modal-content">
              <DialogHeader>
                <DialogTitle className="completion-modal-title">
                  {alreadyScanned ? "Results Available" : "Scan Complete!"}
                </DialogTitle>
                <DialogDescription className="completion-modal-description">
                  {alreadyScanned
                    ? "This extension was previously scanned. Your report is ready to view."
                    : "Your extension scan has finished successfully. You can continue playing the game or view the results now."}
                </DialogDescription>
              </DialogHeader>
              <DialogFooter>
                <Button onClick={handleContinuePlaying} variant="outline">
                  Keep Playing
                </Button>
                <Button onClick={handleViewResults} variant="default">
                  View Results
                </Button>
              </DialogFooter>
            </DialogContent>
          </Dialog>
        </>
      ) : (
        <div className="progress-container">
          {/* Header */}
          <div className="progress-header">
            <Link to="/scan" className="back-link">
              ← Back to Scanner
            </Link>
            <div className="extension-header">
              <img 
                src={extensionLogo} 
                alt="Extension icon" 
                className="extension-logo"
                onError={(e) => {
                  e.target.onerror = null;
                  e.target.src = EXTENSION_ICON_PLACEHOLDER;
                }}
              />
              <div className="extension-header-text">
                <h1 className="progress-title">Scan Status</h1>
                <p className="progress-subtitle">
                  Extension ID: <code>{scanId}</code>
                </p>
              </div>
            </div>
          </div>

          {/* Error State */}
          {error && (
            <div className="error-state">
              <div className="error-icon">❌</div>
              <h2>Scan Failed</h2>
              <p className="error-message">{error}</p>
              <div className="error-actions">
                <Button onClick={() => setError(null)} variant="outline">
                  Dismiss
                </Button>
                <Button onClick={() => navigate("/scan")}>
                  Try Again
                </Button>
              </div>
            </div>
          )}

          {/* No Active Scan State */}
          {!shouldShowGame && !error && (
            <div className="no-scan-state">
              <div className="no-scan-icon">🔍</div>
              <h2>No Active Scan</h2>
              <p>
                There's no active scan for extension ID: <code>{scanId}</code>
                <br />
                The scan may have completed, or you can start a new scan.
              </p>
              <div className="no-scan-actions">
                <Button onClick={() => navigate(`/scan/results/${scanId}`)} variant="default">
                  Check Results
                </Button>
                <Button onClick={() => navigate("/scan")} variant="outline">
                  Start New Scan
                </Button>
                <Button onClick={() => navigate("/scan/history")} variant="outline">
                  View History
                </Button>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
    </>
  );
};

export default ScanProgressPage;

