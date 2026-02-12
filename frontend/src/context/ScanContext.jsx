import React, { createContext, useContext, useState, useCallback, useMemo, useRef, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import realScanService from "../services/realScanService";
import databaseService from "../services/databaseService";
import { normalizeExtensionId } from "../utils/extensionId";
import { useAuth } from "./AuthContext";

const ScanContext = createContext(null);

export const useScan = () => {
  const context = useContext(ScanContext);
  if (!context) {
    throw new Error("useScan must be used within a ScanProvider");
  }
  return context;
};

export const ScanProvider = ({ children }) => {
  const navigate = useNavigate();
  const { isAuthenticated, openSignInModal } = useAuth();

  // Mount guard — prevents setState on unmounted component during long async flows
  const mountedRef = useRef(true);
  useEffect(() => {
    mountedRef.current = true;
    return () => { mountedRef.current = false; };
  }, []);
  
  // Scan state
  const [url, setUrl] = useState("");
  const [isScanning, setIsScanning] = useState(false);
  const [scanStage, setScanStage] = useState(null);
  const [scanResults, setScanResults] = useState(null);
  const [error, setError] = useState(null);
  const [currentExtensionId, setCurrentExtensionId] = useState(null);
  
  // Dashboard stats
  const [dashboardStats, setDashboardStats] = useState({
    totalScans: { value: 0, sparkline: [0] },
    highRisk: { value: 0, sparkline: [0] },
    totalFiles: { value: 0, sparkline: [0] },
    totalVulnerabilities: { value: 0, sparkline: [0] },
  });

  // Scan history
  const [scanHistory, setScanHistory] = useState([]);

  // Load dashboard stats
  const loadDashboardStats = useCallback(async () => {
    try {
      const metrics = await databaseService.getDashboardMetrics();
      setDashboardStats(metrics);
    } catch (err) {
      // console.error("Error loading dashboard stats:", err); // prod: no console
    }
  }, []);

  // Load scan history
  const loadScanHistory = useCallback(async () => {
    try {
      const history = await databaseService.getScanHistory(50);
      setScanHistory(history);
      return history;
    } catch (err) {
      // console.error("Error loading scan history:", err); // prod: no console
      setScanHistory([]);
      return [];
    }
  }, []);

  // Extract extension ID from URL
  const extractExtensionId = useCallback((url) => {
    return realScanService.extractExtensionId(url);
  }, []);

  // Wait for scan completion with stage progression
  const waitForScanCompletion = useCallback(async (extensionId) => {
    const stages = [
      "extracting",
      "security_scan",
      "building_evidence",
      "applying_rules",
      "generating_report",
    ];

    for (let stageIndex = 0; stageIndex < stages.length; stageIndex++) {
      if (!mountedRef.current) return;
      setScanStage(stages[stageIndex]);

      const stageDuration = 10 + Math.random() * 5;
      const steps = Math.ceil(stageDuration / 2);

      for (let step = 0; step < steps; step++) {
        if (!mountedRef.current) return;
        await new Promise((resolve) => setTimeout(resolve, 2000));
        if (!mountedRef.current) return;

        const status = await realScanService.checkScanStatus(extensionId);
        if (!mountedRef.current) return;
        if (status.scanned) {
          setScanStage("generating_report");
          await new Promise((resolve) => setTimeout(resolve, 2000));
          return;
        }

        if (status.status === "failed") {
          // Check for API key errors (401) - show user-friendly message
          if (status.error_code === 401 || status.error?.includes("API key") || status.error?.includes("Invalid API key") || status.error?.includes("Authentication") || status.error?.includes("sk-proj")) {
            throw new Error("Connection is down try back in a while");
          }
          // Check for connection refused errors (503) - LLM service issues
          if (status.error_code === 503 || status.error?.includes("Connection refused") || status.error?.includes("Errno 61") || status.error?.includes("LLM service")) {
            throw new Error("LLM service unavailable. Please check your LLM provider configuration.");
          }
          // Check for quota errors (403) - token/quota exceeded
          if (status.error_code === 403 || status.error?.includes("quota") || status.error?.includes("token_quota")) {
            throw new Error(status.error || "LLM service quota exceeded. Please check your provider limits or add a fallback provider.");
          }
          throw new Error(status.error || "Scan failed on the server.");
        }
      }
    }

    const status = await realScanService.checkScanStatus(extensionId);
    if (status.scanned) {
      return;
    }

    throw new Error("Scan timeout - extension analysis took too long");
  }, []);

  // Start scan from URL
  const startScan = useCallback(async (scanUrl) => {
    const urlToScan = scanUrl || url;
    
    if (!urlToScan.trim()) {
      setError("Please enter a Chrome Web Store URL");
      return;
    }

    // Require authentication before scanning (production, or in dev when VITE_REQUIRE_AUTH_FOR_SCAN=true)
    const isDevelopment = import.meta.env.DEV || import.meta.env.MODE === 'development';
    const requireAuthForScan = import.meta.env.VITE_REQUIRE_AUTH_FOR_SCAN === 'true';
    if ((!isDevelopment || requireAuthForScan) && !isAuthenticated) {
      sessionStorage.setItem("auth:pendingScanUrl", urlToScan);
      sessionStorage.setItem("auth:returnTo", "/scan");
      setError(null); // No error message - modal is the prompt
      openSignInModal();
      return;
    }

    // Clear input state so /scan page starts clean after scan completes
    setUrl("");
    setIsScanning(true);
    setError(null);
    setScanResults(null);
    setCurrentExtensionId(null);
    setScanStage("extracting");

    try {
      const extIdRaw = extractExtensionId(urlToScan);
      if (!extIdRaw) {
        throw new Error("Invalid Chrome Web Store URL format");
      }

      // Normalize the extension ID to ensure it's exactly 32 chars (a-p) and remove any trailing characters
      const extId = normalizeExtensionId(extIdRaw);
      if (!extId) {
        throw new Error("Invalid Chrome extension ID format");
      }

      setCurrentExtensionId(extId);

      // Daily deep-scan limit check (cached lookups still allowed) - skip in development
      const isDevelopment = import.meta.env.DEV || import.meta.env.MODE === 'development';
      if (isDevelopment) {
        // In development, skip limit check - backend will also skip it
      } else {
        try {
          const limit = await realScanService.getDeepScanLimitStatus();
          if (limit?.remaining <= 0) {
            const cached = await realScanService.hasCachedResults(extId);
            if (!cached) {
              setError("Daily deep-scan limit reached. Cached lookups are still unlimited.");
              setScanStage(null);
              setIsScanning(false);
              return;
            }
          }
        } catch (e) {
          // If the limit check fails, fall back to backend enforcement.
        }
      }

      // Navigate to the progress/game screen ASAP for best UX.
      // The progress page will poll status until the scan is running/completed.
      navigate(`/scan/progress/${extId}`);
      
      // Check status and trigger scan in the background
      const status = await realScanService.checkScanStatus(extId);
      let scanTrigger = null;

      if (!status.scanned) {
        scanTrigger = await realScanService.triggerScan(urlToScan);

        // For cached lookups, backend may return status=completed + already_scanned=true
        if (!scanTrigger.already_scanned && scanTrigger.status !== "running") {
          throw new Error(scanTrigger.error || "Failed to start scan");
        }
      }
      
      if (!status.scanned && scanTrigger && !scanTrigger.already_scanned) {
        await waitForScanCompletion(extId);
      }

      // Fetch results (via realScanService.getRealScanResults → GET /api/scan/results/:id)
      const maxAttempts = 10;
      let results = null;
      for (let i = 0; i < maxAttempts; i += 1) {
        // eslint-disable-next-line no-await-in-loop
        results = await realScanService.getRealScanResults(extId);
        if (results) break;
        // eslint-disable-next-line no-await-in-loop
        await new Promise((resolve) => setTimeout(resolve, 1500));
      }

      // Results are already in correct format (no transformation needed)
      setScanResults(results);
      setError("");
      setScanStage(null);
      setIsScanning(false);

      // Refresh stats and history (best-effort)
      await loadScanHistory();
      await loadDashboardStats();

      // IMPORTANT: Do not auto-navigate to results.
      // The progress page will show a "Scan complete" prompt allowing users
      // to keep playing or view results.
    } catch (err) {
      // Check for API key errors (401) - show user-friendly message
      let errorMessage = err.message || "Failed to scan extension.";
      if (err.message?.includes("API key") || err.message?.includes("Invalid API key") || err.message?.includes("Authentication") || err.message?.includes("401")) {
        errorMessage = "Connection is down try back in a while";
      } else if (err.message?.includes("Connection refused") || err.message?.includes("Errno 61") || err.message?.includes("LLM service")) {
        errorMessage = "LLM service unavailable. Please check your LLM provider configuration (LLM_FALLBACK_CHAIN).";
      } else if (err.message?.includes("quota") || err.message?.includes("token_quota") || err.message?.includes("403")) {
        errorMessage = err.message || "LLM service quota exceeded. Please check your provider limits or add a fallback provider.";
      }
      setError(errorMessage);
      setScanStage(null);
      setIsScanning(false);
      // Stay on progress page to show error
    }
  }, [url, extractExtensionId, navigate, waitForScanCompletion, loadScanHistory, loadDashboardStats, isAuthenticated, openSignInModal]);

  // Handle file upload
  const handleFileUpload = useCallback(async (file) => {
    const isDevelopment = import.meta.env.DEV || import.meta.env.MODE === 'development';
    const requireAuthForScan = import.meta.env.VITE_REQUIRE_AUTH_FOR_SCAN === 'true';
    if ((!isDevelopment || requireAuthForScan) && !isAuthenticated) {
      sessionStorage.setItem("auth:returnTo", "/scan");
      setError(null); // No error message - modal is the prompt
      openSignInModal();
      return;
    }

    setUrl("");
    setIsScanning(true);
    setError(null);
    setScanResults(null);
    setCurrentExtensionId(null);
    setScanStage("extracting");

    try {
      // Daily deep-scan limit check (uploads are always deep scans) - skip in development
      if (!isDevelopment) {
        try {
          const limit = await realScanService.getDeepScanLimitStatus();
          if (limit?.remaining <= 0) {
            setError("Daily deep-scan limit reached. Cached lookups are still unlimited.");
            setScanStage(null);
            setIsScanning(false);
            return;
          }
        } catch (e) {
          // If the limit check fails, fall back to backend enforcement.
        }
      }

      const uploadResult = await realScanService.uploadAndScan(file);

      if (!uploadResult || !uploadResult.extension_id) {
        throw new Error("Failed to upload file");
      }

      // Normalize the extension ID to ensure it's exactly 32 chars (a-p) and remove any trailing characters
      const extensionIdRaw = uploadResult.extension_id;
      const extensionId = normalizeExtensionId(extensionIdRaw);
      if (!extensionId) {
        throw new Error("Invalid extension ID format from upload");
      }

      setCurrentExtensionId(extensionId);
      
      // Navigate to progress page
      navigate(`/scan/progress/${extensionId}`);

      await waitForScanCompletion(extensionId);

      // Via realScanService.getRealScanResults → GET /api/scan/results/:id
      const maxAttempts = 10;
      let results = null;
      for (let i = 0; i < maxAttempts; i += 1) {
        // eslint-disable-next-line no-await-in-loop
        results = await realScanService.getRealScanResults(extensionId);
        if (results) break;
        // eslint-disable-next-line no-await-in-loop
        await new Promise((resolve) => setTimeout(resolve, 1500));
      }
      // Results are already in correct format (no transformation needed)
      setScanResults(results);
      setError("");
      setScanStage(null);
      setIsScanning(false);

      await loadScanHistory();
      await loadDashboardStats();
      // Do not auto-navigate; progress page will prompt.
    } catch (err) {
      setError(err.message || "Failed to upload and scan file.");
      setScanStage(null);
      setIsScanning(false);
    }
  }, [navigate, waitForScanCompletion, loadScanHistory, loadDashboardStats, isAuthenticated, openSignInModal]);

  // Load scan from history (single API: realScanService.getRealScanResults)
  const loadScanFromHistory = useCallback(async (extId) => {
    try {
      const data = await realScanService.getRealScanResults(extId);
      if (!data) {
        setError("Scan results not found.");
        return;
      }
      setScanResults(data);
      setCurrentExtensionId(extId);
      setError("");
      navigate(`/scan/results/${extId}`);
    } catch (err) {
      setError("Failed to load scan results from history.");
    }
  }, [navigate]);

  // Load results by extension ID (single API: realScanService.getRealScanResults)
  // Always clears previous results first so stale data never leaks between extensions.
  const loadResultsById = useCallback(async (extId) => {
    try {
      // Clear previous extension's data before fetching new one
      setScanResults(null);
      setCurrentExtensionId(extId);
      setError("");

      const data = await realScanService.getRealScanResults(extId);
      if (!data) {
        setError("Scan results not found. The extension may not have been scanned yet.");
        return null;
      }
      setScanResults(data);
      setCurrentExtensionId(extId);
      return data;
    } catch (err) {
      setError("Failed to load scan results.");
      return null;
    }
  }, []);

  // Clear scan state
  const clearScan = useCallback(() => {
    setUrl("");
    setIsScanning(false);
    setScanStage(null);
    setScanResults(null);
    setError(null);
    setCurrentExtensionId(null);
  }, []);

  const value = useMemo(() => ({
    // State
    url,
    setUrl,
    isScanning,
    scanStage,
    scanResults,
    setScanResults,
    error,
    setError,
    currentExtensionId,
    dashboardStats,
    scanHistory,
    
    // Actions
    startScan,
    handleFileUpload,
    loadScanFromHistory,
    loadResultsById,
    loadDashboardStats,
    loadScanHistory,
    extractExtensionId,
    clearScan,
  }), [
    url, isScanning, scanStage, scanResults, error,
    currentExtensionId, dashboardStats, scanHistory,
    startScan, handleFileUpload, loadScanFromHistory,
    loadResultsById, loadDashboardStats, loadScanHistory,
    extractExtensionId, clearScan,
  ]);

  return (
    <ScanContext.Provider value={value}>
      {children}
    </ScanContext.Provider>
  );
};

export default ScanContext;

