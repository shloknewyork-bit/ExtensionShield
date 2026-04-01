/**
 * Database Service
 *
 * Handles communication with the backend API for persistent storage.
 * Backend uses Postgres (Supabase) in production; SQLite is a dev fallback.
 */

import { getScanResultsUrl } from "../utils/constants";
import { fetchJson, buildFetchError } from "./requestHelpers";

class DatabaseService {
  constructor() {
    // Use environment variable for API URL, default to empty string for same-origin (production)
    // For local development, set VITE_API_URL=http://localhost:8007 in .env.local
    this.baseURL = import.meta.env.VITE_API_URL || "";
    this.API_BASE_URL = `${this.baseURL}/api`;
    this.accessToken = null;
    this.historyUnavailable = false;
  }

  setAccessToken(token) {
    this.accessToken = token || null;
  }

  _authHeaders(tokenOverride = undefined) {
    const token = tokenOverride !== undefined ? tokenOverride : this.accessToken;
    if (!token) return {};
    return { Authorization: `Bearer ${token}` };
  }

  _isHistoryNotImplemented(response, body, error) {
    const status = response?.status ?? error?.status;
    const detail = body?.detail ?? error?.detail;
    return (
      status === 501 &&
      detail &&
      typeof detail === "object" &&
      detail.error === "not_implemented" &&
      detail.feature === "history"
    );
  }
  /**
   * Get statistics from the database
   */
  async getStatistics() {
    try {
      const { response, body } = await fetchJson(`${this.API_BASE_URL}/statistics`);
      if (!response.ok) {
        throw buildFetchError(response, body, "Failed to fetch statistics");
      }
      return body;
    } catch (error) {
      // console.error("Error fetching statistics:", error); // prod: no console
      return {
        total_scans: 0,
        high_risk_extensions: 0,
        total_files_analyzed: 0,
        total_vulnerabilities: 0,
        avg_security_score: 0,
        risk_distribution: { high: 0, medium: 0, low: 0 },
      };
    }
  }

  /**
   * Get scan history from the database
   */
  async getScanHistory(limit = 50, accessToken = undefined) {
    if (this.historyUnavailable) return [];
    try {
      const { response, body } = await fetchJson(
        `${this.API_BASE_URL}/history?limit=${limit}`,
        {
          headers: {
            ...this._authHeaders(accessToken),
          },
        }
      );
      if (!response.ok) {
        if (response.status === 401) return [];
        if (this._isHistoryNotImplemented(response, body)) {
          this.historyUnavailable = true;
          return [];
        }
        throw buildFetchError(response, body, "Failed to fetch scan history");
      }
      const historyPayload = body || {};
      if (Array.isArray(historyPayload)) return historyPayload;
      return historyPayload.history || [];
    } catch (error) {
      if (this._isHistoryNotImplemented(null, null, error)) {
        this.historyUnavailable = true;
        return [];
      }
      // console.error("Error fetching scan history:", error); // prod: no console
      return [];
    }
  }

  /**
   * Get private scan history (uploaded CRX/ZIP builds only)
   */
  async getPrivateScanHistory(limit = 50, accessToken = undefined) {
    if (this.historyUnavailable) return [];
    try {
      const { response, body } = await fetchJson(
        `${this.API_BASE_URL}/history/private?limit=${limit}`,
        {
          headers: {
            ...this._authHeaders(accessToken),
          },
        }
      );
      if (!response.ok) {
        if (response.status === 401) return [];
        if (this._isHistoryNotImplemented(response, body)) {
          this.historyUnavailable = true;
          return [];
        }
        throw buildFetchError(response, body, "Failed to fetch private scan history");
      }
      const historyPayload = body || {};
      if (Array.isArray(historyPayload)) return historyPayload;
      return historyPayload.history || [];
    } catch (error) {
      if (this._isHistoryNotImplemented(null, null, error)) {
        this.historyUnavailable = true;
      }
      return [];
    }
  }

  /**
   * Get recent scans from the database (Postgres/SQLite).
   * @param {number} limit - Max rows to return
   * @param {string} [search] - Optional filter by extension name or ID (server-side)
   */
  async getRecentScans(limit = 10, search = "") {
    try {
      let url = `${this.API_BASE_URL}/recent?limit=${limit}`;
      if (search && search.trim()) {
        url += `&search=${encodeURIComponent(search.trim())}`;
      }
      // console.log(`[databaseService] Fetching recent scans from: ${url}`); // prod: no console
      
      const { response, body } = await fetchJson(url);
      if (!response.ok) {
        throw buildFetchError(response, body, `Failed to fetch recent scans`);
      }

      if (Array.isArray(body)) return body;
      if (body?.recent && Array.isArray(body.recent)) return body.recent;
      return [];
    } catch (error) {
      // console.error("[databaseService] Error fetching recent scans:", error); // prod: no console
      // console.error("[databaseService] Error details:", { message: error.message, stack: error.stack, name: error.name }); // prod: no console
      // Return empty array to prevent UI crashes, but log the error
      return [];
    }
  }

  /**
   * Get scan result by extension ID.
   * Single API: GET /api/scan/results/{extensionId} (URL from constants).
   * Returns payload as-is from backend (no transformation).
   */
  async getScanResult(extensionId) {
    try {
      const url = getScanResultsUrl(extensionId);
      if (!url) return null;

      const { response, body } = await fetchJson(url, {
        headers: {
          ...this._authHeaders(),
        },
      });
      
      if (!response.ok) {
        if (response.status === 404) {
          return null;
        }
        throw buildFetchError(response, body, "Failed to fetch scan result");
      }
      
      // console.log("TOP_KEYS", Object.keys(body || {})); // prod: no console
      return body;
    } catch (error) {
      // console.error("Error fetching scan result:", error); // prod: no console
      return null;
    }
  }

  /**
   * Delete a scan result
   */
  async deleteScanResult(extensionId) {
    try {
      const response = await fetch(`${this.API_BASE_URL}/scan/${extensionId}`, {
        method: "DELETE"
      });
      if (!response.ok) {
        throw new Error("Failed to delete scan result");
      }
      return true;
    } catch (error) {
      // console.error("Error deleting scan result:", error); // prod: no console
      return false;
    }
  }

  /**
   * Clear all scan results
   */
  async clearAllResults() {
    try {
      const response = await fetch(`${this.API_BASE_URL}/clear`, {
        method: "POST"
      });
      if (!response.ok) {
        throw new Error("Failed to clear all results");
      }
      return true;
    } catch (error) {
      // console.error("Error clearing all results:", error); // prod: no console
      return false;
    }
  }

  /**
   * Check if a scan result exists in the database
   */
  async hasScanResult(extensionId) {
    const result = await this.getScanResult(extensionId);
    return result !== null;
  }

  /**
   * Get aggregated metrics for dashboard widgets (history only when authenticated to avoid 401)
   */
  async getDashboardMetrics() {
    const stats = await this.getStatistics();
    const history = this.accessToken
      ? await this.getScanHistory(20, this.accessToken)
      : [];
    const recentSource = this.historyUnavailable
      ? await this.getRecentScans(20)
      : history;

    // Get last 7 scans for sparkline (most recent first, then reverse for chronological order)
    const recentScans = recentSource.slice(0, 7).reverse();
    
    // If no scans, return zeros
    if (recentScans.length === 0) {
      return {
        totalScans: { value: 0, sparkline: [0] },
        highRisk: { value: 0, sparkline: [0] },
        totalFiles: { value: 0, sparkline: [0] },
        totalVulnerabilities: { value: 0, sparkline: [0] },
        avgSecurityScore: 0,
        riskDistribution: { high: 0, medium: 0, low: 0 }
      };
    }

    // Calculate actual data points (not cumulative) for sparklines
    const scanCountSparkline = recentScans.map((_, idx) => idx + 1);
    
    // High risk count at each point in time (cumulative makes sense here)
    const highRiskSparkline = [];
    let highRiskRunning = 0;
    recentScans.forEach(scan => {
      if ((scan.risk_level || "").toLowerCase() === "high") {
        highRiskRunning++;
      }
      highRiskSparkline.push(highRiskRunning);
    });
    
    // Files per scan (actual values, not cumulative)
    const filesSparkline = recentScans.map(scan => scan.total_files || 0);
    
    // Findings per scan (actual values, not cumulative)
    const findingsSparkline = recentScans.map(scan => scan.total_findings || 0);

    return {
      totalScans: {
        value: stats.total_scans || 0,
        sparkline: scanCountSparkline
      },
      highRisk: {
        value: stats.high_risk_extensions || 0,
        sparkline: highRiskSparkline.length > 0 ? highRiskSparkline : [0]
      },
      totalFiles: {
        value: stats.total_files_analyzed || 0,
        sparkline: filesSparkline.length > 0 ? filesSparkline : [0]
      },
      totalVulnerabilities: {
        value: stats.total_vulnerabilities || 0,
        sparkline: findingsSparkline.length > 0 ? findingsSparkline : [0]
      },
      avgSecurityScore: stats.avg_security_score || 0,
      riskDistribution: stats.risk_distribution || { high: 0, medium: 0, low: 0 }
    };
  }
}

export default new DatabaseService();
