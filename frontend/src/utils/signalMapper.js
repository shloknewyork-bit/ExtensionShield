/**
 * Signal Mapper Utility
 * 
 * Maps scan results to ExtensionShield's three-layer scoring system:
 * - Security: Security layer score (SAST, vulnerabilities, code quality)
 * - Privacy: Privacy layer score (permissions, data exfiltration, network)
 * - Governance: Governance layer score (policy compliance, behavioral consistency)
 * 
 * Uses scoring_v2 layer scores as the primary source of truth.
 * Falls back to legacy CODE/PERMS/INTEL calculation if scoring_v2 is unavailable.
 */

// Signal levels
export const SIGNAL_LEVELS = {
  OK: 'ok',
  WARN: 'warn',
  HIGH: 'high'
};

// Score thresholds for Security and Privacy layers (0-100 scale)
// Green: 85-100, Yellow: 60-84, Red: 0-59
const SECURITY_PRIVACY_THRESHOLDS = {
  HIGH: 59,   // 0-59: HIGH (red) - Critical/Bad
  WARN: 84    // 60-84: WARN (yellow) - Review/Warning, 85-100: OK (green) - Good/Clean
};

// Score thresholds for Governance layer (same thresholds for consistency)
const GOVERNANCE_THRESHOLDS = {
  HIGH: 59,   // 0-59: HIGH (red) - Non-compliant
  WARN: 84    // 60-84: WARN (yellow) - Review, 85-100: OK (green) - Compliant
};

// Legacy thresholds (for backward compatibility)
const THRESHOLDS = {
  PERMISSIONS: {
    HIGH_COUNT_WARN: 2,
    HIGH_COUNT_HIGH: 4
  },
  SAST: {
    CRITICAL_HIGH: 1,
    HIGH_WARN: 2,
    MEDIUM_WARN: 5
  },
  ENTROPY: {
    OBFUSCATED_WARN: 1,
    OBFUSCATED_HIGH: 3
  },
  VIRUSTOTAL: {
    MALICIOUS_WARN: 1,
    MALICIOUS_HIGH: 3
  }
};

/**
 * Calculate Security signal from scoring_v2.security_score
 * Falls back to legacy CODE signal calculation if scoring_v2 is unavailable
 */
export function calculateSecuritySignal(scanResult) {
  const scoringV2 = scanResult?.scoring_v2 || {};
  const securityScore = scoringV2?.security_score;
  
  // If we have scoring_v2 security_score, use it directly
  if (securityScore !== undefined && securityScore !== null) {
    let level = SIGNAL_LEVELS.OK;
    let label = 'Good';
    
    if (securityScore <= SECURITY_PRIVACY_THRESHOLDS.HIGH) {
      level = SIGNAL_LEVELS.HIGH;
      // Check for critical gates
      const hardGates = scoringV2?.hard_gates_triggered || [];
      const hasCriticalGate = hardGates.some(gate => 
        gate.includes('CRITICAL') || gate.includes('CRITICAL_SAST')
      );
      label = hasCriticalGate ? 'Critical' : 'Bad';
    } else if (securityScore <= SECURITY_PRIVACY_THRESHOLDS.WARN) {
      level = SIGNAL_LEVELS.WARN;
      label = 'Review';
    } else {
      level = SIGNAL_LEVELS.OK;
      label = 'Good';
    }
    
    return { level, label, score: securityScore };
  }
  
  // Fallback to legacy CODE signal calculation
  return calculateCodeSignal(scanResult);
}

/**
 * Calculate Privacy signal from scoring_v2.privacy_score
 * Falls back to legacy PERMS signal calculation if scoring_v2 is unavailable
 */
export function calculatePrivacySignal(scanResult) {
  const scoringV2 = scanResult?.scoring_v2 || {};
  const privacyScore = scoringV2?.privacy_score;
  
  // If we have scoring_v2 privacy_score, use it directly
  if (privacyScore !== undefined && privacyScore !== null) {
    let level = SIGNAL_LEVELS.OK;
    let label = 'Good';
    
    if (privacyScore <= SECURITY_PRIVACY_THRESHOLDS.HIGH) {
      level = SIGNAL_LEVELS.HIGH;
      label = 'Bad';
    } else if (privacyScore <= SECURITY_PRIVACY_THRESHOLDS.WARN) {
      level = SIGNAL_LEVELS.WARN;
      label = 'Warning';
    } else {
      level = SIGNAL_LEVELS.OK;
      label = 'Good';
    }
    
    return { level, label, score: privacyScore };
  }
  
  // Fallback to legacy PERMS signal calculation
  return calculatePermsSignal(scanResult);
}

/**
 * Calculate Governance signal from scoring_v2.governance_score
 * Falls back to legacy INTEL signal calculation if scoring_v2 is unavailable
 */
export function calculateGovernanceSignal(scanResult) {
  const scoringV2 = scanResult?.scoring_v2 || {};
  const governanceScore = scoringV2?.governance_score;
  
  // If we have scoring_v2 governance_score, use it directly
  if (governanceScore !== undefined && governanceScore !== null) {
    let level = SIGNAL_LEVELS.OK;
    let label = 'Compliant';
    
    if (governanceScore <= GOVERNANCE_THRESHOLDS.HIGH) {
      level = SIGNAL_LEVELS.HIGH;
      label = 'Non-compliant';
    } else if (governanceScore <= GOVERNANCE_THRESHOLDS.WARN) {
      level = SIGNAL_LEVELS.WARN;
      label = 'Review';
    } else {
      level = SIGNAL_LEVELS.OK;
      label = 'Compliant';
    }
    
    return { level, label, score: governanceScore };
  }
  
  // Fallback to legacy INTEL signal calculation
  return calculateIntelSignal(scanResult);
}

/**
 * Calculate all signals for a scan result
 * Uses Security/Privacy/Governance from scoring_v2, falls back to legacy CODE/PERMS/INTEL
 */
export function calculateAllSignals(scanResult) {
  return {
    security_signal: calculateSecuritySignal(scanResult),
    privacy_signal: calculatePrivacySignal(scanResult),
    governance_signal: calculateGovernanceSignal(scanResult),
    // Keep legacy signals for backward compatibility
    code_signal: calculateCodeSignal(scanResult),
    perms_signal: calculatePermsSignal(scanResult),
    intel_signal: calculateIntelSignal(scanResult)
  };
}

// ============================================================================
// Legacy signal calculation functions (for backward compatibility)
// ============================================================================

/**
 * Calculate code signal from SAST and entropy analysis (LEGACY)
 */
function calculateCodeSignal(scanResult) {
  const sastResults = scanResult?.sast_results || scanResult?.sastResults || {};
  const entropyAnalysis = scanResult?.entropy_analysis || scanResult?.entropyAnalysis || {};
  const scoringV2 = scanResult?.scoring_v2 || {};
  
  // Check if scoring_v2 indicates critical issues (hard gates triggered)
  const hardGates = scoringV2?.hard_gates_triggered || [];
  const hasCriticalGate = hardGates.some(gate => 
    gate.includes('CRITICAL') || gate.includes('CRITICAL_SAST')
  );
  
  // Count SAST findings by severity
  const findings = sastResults?.sast_findings || sastResults?.findings || {};
  let criticalCount = 0;
  let highCount = 0;
  let mediumCount = 0;
  
  Object.values(findings).forEach(fileFindings => {
    if (Array.isArray(fileFindings)) {
      fileFindings.forEach(finding => {
        const severity = (finding.extra?.severity || finding.severity || finding.check_id || '').toUpperCase();
        if (severity.includes('CRITICAL') || finding.check_id?.includes('CRITICAL')) {
          criticalCount++;
        } else if (severity === 'HIGH' || severity === 'ERROR' || severity.includes('HIGH')) {
          highCount++;
        } else if (severity === 'MEDIUM' || severity === 'WARNING' || severity.includes('MEDIUM')) {
          mediumCount++;
        }
      });
    }
  });
  
  // Check obfuscation
  const obfuscatedFiles = entropyAnalysis?.obfuscated_files || entropyAnalysis?.obfuscatedFiles || 0;
  
  // Determine signal level
  let level = SIGNAL_LEVELS.OK;
  let label = 'Clean';
  
  if (hasCriticalGate || criticalCount >= THRESHOLDS.SAST.CRITICAL_HIGH) {
    level = SIGNAL_LEVELS.HIGH;
    label = hasCriticalGate ? 'Critical' : `${criticalCount} critical`;
  } else if (highCount >= THRESHOLDS.SAST.HIGH_WARN || obfuscatedFiles >= THRESHOLDS.ENTROPY.OBFUSCATED_HIGH) {
    level = SIGNAL_LEVELS.HIGH;
    const issues = [];
    if (highCount > 0) issues.push(`${highCount} high`);
    if (obfuscatedFiles > 0) issues.push(`${obfuscatedFiles} obfusc`);
    label = issues.join(', ');
  } else if (mediumCount >= THRESHOLDS.SAST.MEDIUM_WARN || obfuscatedFiles >= THRESHOLDS.ENTROPY.OBFUSCATED_WARN) {
    level = SIGNAL_LEVELS.WARN;
    const issues = [];
    if (mediumCount > 0) issues.push(`${mediumCount} med`);
    if (obfuscatedFiles > 0) issues.push(`${obfuscatedFiles} obfusc`);
    label = issues.join(', ');
  } else if (criticalCount > 0 || highCount > 0 || mediumCount > 0) {
    level = SIGNAL_LEVELS.WARN;
    const total = criticalCount + highCount + mediumCount;
    label = `${total} issue${total !== 1 ? 's' : ''}`;
  }
  
  return { level, label };
}

/**
 * Calculate permissions signal from permissions analysis (LEGACY)
 */
function calculatePermsSignal(scanResult) {
  const permsAnalysis = scanResult?.permissions_analysis || scanResult?.permissionsAnalysis || {};
  const permissions = permsAnalysis?.permissions_details || permsAnalysis?.permissions || [];
  
  // Count high-risk permissions
  let highRiskCount = 0;
  let mediumRiskCount = 0;
  
  const permissionsList = Array.isArray(permissions) ? permissions : Object.values(permissions);
  
  permissionsList.forEach(perm => {
    const risk = (perm.risk || perm.risk_level || '').toLowerCase();
    if (risk === 'high' || risk === 'critical') highRiskCount++;
    else if (risk === 'medium') mediumRiskCount++;
  });
  
  // Also check manifest for dangerous permissions
  const manifest = scanResult?.manifest || {};
  const dangerousPerms = ['<all_urls>', 'webRequest', 'webRequestBlocking', 'clipboardRead', 
                          'history', 'management', 'nativeMessaging', 'debugger'];
  
  const allPerms = [
    ...(manifest.permissions || []),
    ...(manifest.host_permissions || [])
  ];
  
  allPerms.forEach(p => {
    if (dangerousPerms.some(dp => p.includes(dp))) {
      highRiskCount++;
    }
  });
  
  // Determine signal level
  let level = SIGNAL_LEVELS.OK;
  let label = 'Minimal';
  
  if (highRiskCount >= THRESHOLDS.PERMISSIONS.HIGH_COUNT_HIGH) {
    level = SIGNAL_LEVELS.HIGH;
    label = `${highRiskCount} high-risk`;
  } else if (highRiskCount >= THRESHOLDS.PERMISSIONS.HIGH_COUNT_WARN) {
    level = SIGNAL_LEVELS.WARN;
    label = `${highRiskCount} high`;
  } else if (mediumRiskCount > 2) {
    level = SIGNAL_LEVELS.WARN;
    label = `${mediumRiskCount} medium`;
  } else if (highRiskCount > 0) {
    level = SIGNAL_LEVELS.WARN;
    label = `${highRiskCount} sensitive`;
  }
  
  return { level, label };
}

/**
 * Calculate intel signal from VirusTotal and threat intelligence (LEGACY)
 */
function calculateIntelSignal(scanResult) {
  const vtAnalysis = scanResult?.virustotal_analysis || scanResult?.virustotalAnalysis || {};
  
  const maliciousCount = vtAnalysis?.total_malicious || vtAnalysis?.malicious || 0;
  const suspiciousCount = vtAnalysis?.total_suspicious || vtAnalysis?.suspicious || 0;
  
  // Determine signal level
  let level = SIGNAL_LEVELS.OK;
  let label = '0 flags';
  
  if (maliciousCount >= THRESHOLDS.VIRUSTOTAL.MALICIOUS_HIGH) {
    level = SIGNAL_LEVELS.HIGH;
    label = `${maliciousCount} malicious`;
  } else if (maliciousCount >= THRESHOLDS.VIRUSTOTAL.MALICIOUS_WARN) {
    level = SIGNAL_LEVELS.HIGH;
    label = `${maliciousCount} flagged`;
  } else if (suspiciousCount > 2) {
    level = SIGNAL_LEVELS.WARN;
    label = `${suspiciousCount} suspicious`;
  } else if (maliciousCount > 0 || suspiciousCount > 0) {
    level = SIGNAL_LEVELS.WARN;
    const total = maliciousCount + suspiciousCount;
    label = `${total} flag${total !== 1 ? 's' : ''}`;
  }
  
  return { level, label };
}

/**
 * Determine risk level from score
 * Thresholds: Green (85-100), Yellow (60-84), Red (0-59)
 */
export function getRiskLevel(score) {
  if (score >= 85) return 'LOW';
  if (score >= 60) return 'MEDIUM';
  return 'HIGH';
}

/**
 * Get risk color class based on level
 */
export function getRiskColorClass(level) {
  switch (level?.toUpperCase()) {
    case 'LOW':
      return 'risk-low';
    case 'MED':
    case 'MEDIUM':
      return 'risk-medium';
    case 'MODERATE':
      // Legacy value - map to red under current threshold policy.
      return 'risk-high';
    case 'HIGH':
    case 'CRITICAL':
      return 'risk-high';
    default:
      return 'risk-unknown';
  }
}

/**
 * Get signal color class based on level
 */
export function getSignalColorClass(level) {
  switch (level) {
    case SIGNAL_LEVELS.OK:
      return 'signal-ok';
    case SIGNAL_LEVELS.WARN:
      return 'signal-warn';
    case SIGNAL_LEVELS.HIGH:
      return 'signal-high';
    default:
      return 'signal-unknown';
  }
}

/**
 * Count total findings from scan result
 */
export function countFindings(scanResult) {
  const riskDist = scanResult?.risk_distribution || scanResult?.riskDistribution || {};
  return (riskDist.high || 0) + (riskDist.medium || 0) + (riskDist.low || 0);
}

/**
 * Get top finding summary (single line)
 */
export function getTopFindingSummary(scanResult) {
  const sastResults = scanResult?.sast_results || scanResult?.sastResults || {};
  const findings = sastResults?.sast_findings || sastResults?.findings || {};
  
  // Find the highest severity finding
  let topFinding = null;
  const severityOrder = ['CRITICAL', 'HIGH', 'ERROR', 'MEDIUM', 'WARNING', 'LOW', 'INFO'];
  
  for (const severity of severityOrder) {
    for (const fileFindings of Object.values(findings)) {
      if (Array.isArray(fileFindings)) {
        const match = fileFindings.find(f => 
          (f.extra?.severity || f.severity || '').toUpperCase() === severity
        );
        if (match) {
          topFinding = match;
          break;
        }
      }
    }
    if (topFinding) break;
  }
  
  if (topFinding) {
    const message = topFinding.extra?.message || topFinding.message || topFinding.check_id || 'Security issue detected';
    // Truncate to ~60 chars
    return message.length > 60 ? message.substring(0, 57) + '...' : message;
  }
  
  return null;
}

/**
 * Map risk level from various formats to UI format
 */
function normalizeRiskLevel(riskLevel) {
  if (!riskLevel) return null;
  
  const riskStr = String(riskLevel).toUpperCase();
  
  // Handle scoring_v2 format: "critical", "high", "medium", "low", "none"
  if (riskStr === 'CRITICAL') return 'HIGH';
  if (riskStr === 'HIGH') return 'HIGH';
  if (riskStr === 'MEDIUM' || riskStr === 'MED' || riskStr === 'MODERATE') return 'MEDIUM';
  if (riskStr === 'LOW' || riskStr === 'NONE') return 'LOW';
  
  return riskStr; // Return as-is if unknown format
}

/**
 * Enrich scan data with signals and risk info
 */
export function enrichScanWithSignals(scan, fullResult) {
  // Prefer risk_and_signals mapping from API if available (new format)
  const riskAndSignals = fullResult?.risk_and_signals || scan?.risk_and_signals || {};
  const apiSignals = riskAndSignals.signals || {};
  const apiSecurityScore = Number(apiSignals.security);
  const apiPrivacyScore = Number(apiSignals.privacy);
  const apiGovernanceScore = Number(apiSignals.gov);
  
  // Use risk score from API mapping if available
  const apiRiskScore = Number.isFinite(Number(riskAndSignals.risk))
    ? Number(riskAndSignals.risk)
    : null;
  const apiTotalFindings = Number.isFinite(Number(riskAndSignals.total_findings))
    ? Number(riskAndSignals.total_findings)
    : null;
  const hasAllApiLayerScores =
    Number.isFinite(apiSecurityScore) &&
    Number.isFinite(apiPrivacyScore) &&
    Number.isFinite(apiGovernanceScore);
  
  // Prefer risk level from scoring_v2 if available (most up-to-date)
  let riskLevel = null;
  if (fullResult?.scoring_v2?.risk_level) {
    // scoring_v2 uses lowercase: "critical", "high", "medium", "low", "none"
    riskLevel = normalizeRiskLevel(fullResult.scoring_v2.risk_level);
  } else if (apiRiskScore !== null) {
    // Calculate risk from API risk score
    riskLevel = getRiskLevel(apiRiskScore);
  } else if (fullResult?.scoring_v2?.overall_score !== undefined) {
    // Calculate risk from scoring_v2 overall_score if risk_level not available
    riskLevel = getRiskLevel(fullResult.scoring_v2.overall_score);
  } else {
    // Fallback to legacy fields
    const legacyRisk = fullResult?.overall_risk || fullResult?.risk_level;
    riskLevel = legacyRisk ? normalizeRiskLevel(legacyRisk) : null;
  }
  
  // Calculate score - prefer API risk score, then scoring_v2 overall_score
  const score = apiRiskScore !== null
    ? apiRiskScore
    : (fullResult?.scoring_v2?.overall_score !== undefined 
      ? fullResult.scoring_v2.overall_score
      : (fullResult?.overall_security_score || fullResult?.security_score || scan?.security_score || 0));
  
  // If we still don't have a risk level, calculate it from score
  if (!riskLevel) {
    riskLevel = getRiskLevel(score);
  }
  
  // Use API total findings if available, otherwise calculate
  const findingsCount = apiTotalFindings !== null
    ? apiTotalFindings
    : (fullResult?.total_findings || countFindings(fullResult) || 0);
  
  // Calculate signals - prefer API signals if available, otherwise calculate from fullResult
  let signals;
  if (hasAllApiLayerScores) {
    // Use API signals and calculate signal levels from scores
    signals = {
      security_signal: calculateSecuritySignal({ scoring_v2: { security_score: apiSecurityScore } }),
      privacy_signal: calculatePrivacySignal({ scoring_v2: { privacy_score: apiPrivacyScore } }),
      governance_signal: calculateGovernanceSignal({ scoring_v2: { governance_score: apiGovernanceScore } }),
      // Legacy signals for backward compatibility
      code_signal: calculateSecuritySignal({ scoring_v2: { security_score: apiSecurityScore } }),
      perms_signal: calculatePrivacySignal({ scoring_v2: { privacy_score: apiPrivacyScore } }),
      intel_signal: calculateGovernanceSignal({ scoring_v2: { governance_score: apiGovernanceScore } }),
    };
  } else {
    // Fallback to calculating from fullResult
    signals = calculateAllSignals(fullResult);
  }
  
  return {
    ...scan,
    score,
    risk_level: riskLevel,
    findings_count: findingsCount,
    top_finding_summary: getTopFindingSummary(fullResult),
    signals,
    last_scanned_at: scan.timestamp || fullResult?.timestamp
  };
}

export default {
  calculateSecuritySignal,
  calculatePrivacySignal,
  calculateGovernanceSignal,
  calculateAllSignals,
  getRiskLevel,
  getRiskColorClass,
  getSignalColorClass,
  countFindings,
  getTopFindingSummary,
  enrichScanWithSignals,
  SIGNAL_LEVELS
};
