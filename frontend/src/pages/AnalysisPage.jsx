import React, { useState, useEffect, useRef } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import databaseService from "../services/databaseService";
import realScanService from "../services/realScanService";
import TabbedResultsPanel from "../components/TabbedResultsPanel";
import { Search } from "lucide-react";
import { Button } from "../components/ui/button";

const AnalysisPage = () => {
  const [scanResults, setScanResults] = useState(null);
  const [loading, setLoading] = useState(true);
  const location = useLocation();
  const navigate = useNavigate();

  useEffect(() => {
    let isMounted = true;
    
    const loadData = async () => {
      setLoading(true);
      
      // Safety timeout
      const safetyTimeout = setTimeout(() => {
        if (isMounted) {
          setLoading(false);
        }
      }, 3000);

      try {
        // 1. Try to get ID from URL query params
        const params = new URLSearchParams(location.search);
        let scanId = params.get("id");

        // 2. Fallback: Get most recent scan from history if no ID provided
        if (!scanId) {
          const timeoutPromise = new Promise((_, reject) =>
            setTimeout(() => reject(new Error('Request timeout')), 5000)
          );
          const historyPromise = databaseService.getScanHistory(1);
          const history = await Promise.race([historyPromise, timeoutPromise]);
          
          if (history.length > 0) {
            scanId = history[0].extension_id;
            // Update URL with the ID so refresh works correctly
            if (isMounted) {
              navigate(`/analysis?id=${scanId}`, { replace: true });
            }
          }
        }

        // 3. Load scan results if we have an ID
        if (scanId && isMounted) {
          const timeoutPromise = new Promise((_, reject) =>
            setTimeout(() => reject(new Error('Request timeout')), 5000)
          );
          const resultPromise = databaseService.getScanResult(scanId);
          const dbResult = await Promise.race([resultPromise, timeoutPromise]);
          
          if (dbResult && isMounted) {
            // Format raw database results for TabbedResultsPanel
            const formattedResults = realScanService.formatRealResults(dbResult);
            setScanResults(formattedResults);
          }
        }
      } catch (error) {
        console.error("Failed to load analysis data:", error);
      } finally {
        clearTimeout(safetyTimeout);
        if (isMounted) {
          setLoading(false);
        }
      }
    };

    loadData();

    return () => {
      isMounted = false;
    };
  }, [location.search, navigate]);

  // Mock handlers since AnalysisPage is read-only view of past results mainly
  const handleViewFile = (file) => alert(`View file: ${file.name}`);
  const handleAnalyzeWithAI = (file) => alert(`AI analysis for ${file.name}`);
  const handleViewFindingDetails = (finding) => alert(finding.title);
  const handleViewAllFindings = () => alert("All findings view");

  if (loading) {
    return (
      <div className="page-container flex items-center justify-center min-h-[50vh]">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary"></div>
      </div>
    );
  }

  if (!scanResults) {
    return (
      <div className="page-container">
        <div className="page-header">
          <h1 className="page-title">🔬 Analysis Center</h1>
          <p className="page-subtitle">Detailed security reports and code insights</p>
        </div>
        <div className="glass-card flex flex-col items-center justify-center py-20 text-center">
          <div className="bg-surface-elevated/50 p-6 rounded-full mb-6">
            <Search className="h-12 w-12 text-muted-foreground opacity-50" />
          </div>
          <h2 className="text-2xl font-bold mb-2">No Analysis Data Available</h2>
          <p className="text-muted-foreground max-w-md mb-8">
            Run a new scan from the Dashboard or select a previous scan from History to view detailed analysis.
          </p>
          <Button onClick={() => navigate("/")}>Go to Dashboard</Button>
        </div>
      </div>
    );
  }

  return (
    <div className="page-container">
      <div className="page-header">
        <h1 className="page-title">🔬 Analysis Report: {scanResults.name || scanResults.extensionId}</h1>
        <p className="page-subtitle">
          Detailed security analysis and findings
        </p>
      </div>

      <div className="glass-card">
        <TabbedResultsPanel
          scanResults={scanResults}
          onViewFile={handleViewFile}
          onAnalyzeWithAI={handleAnalyzeWithAI}
          onViewFindingDetails={handleViewFindingDetails}
          onViewAllFindings={handleViewAllFindings}
        />
      </div>
    </div>
  );
};

export default AnalysisPage;