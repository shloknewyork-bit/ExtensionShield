import React, { useState } from 'react';
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from '../ui/dialog';
import FactorBars from './FactorBars';
import PermissionsPanel from './PermissionsPanel';
import './LayerModal.scss';

/**
 * LayerModal - Modal showing detailed layer information
 * 
 * Props:
 * - open: boolean
 * - onClose: () => void
 * - layer: 'security' | 'privacy' | 'governance'
 * - score: number | null
 * - band: 'GOOD' | 'WARN' | 'BAD' | 'NA'
 * - factors: FactorVM[]
 * - permissions: PermissionsVM (for privacy modal)
 * - powerfulPermissions: string[] (for security modal - subset)
 * - keyFindings: KeyFindingVM[] (filtered by layer)
 * - gateResults: any[] (filtered by layer)
 * - layerReasons: string[] (filtered by layer)
 * - layerDetails: object | null (human-friendly explanations)
 * - onViewEvidence: (evidenceIds: string[]) => void
 */
const LayerModal = ({
  open,
  onClose,
  layer,
  score = null,
  band = 'NA',
  factors = [],
  permissions = null,
  powerfulPermissions = [],
  keyFindings = [],
  gateResults = [],
  layerReasons = [],
  layerDetails = null,
  onViewEvidence = null,
}) => {
  const [expandedSection, setExpandedSection] = useState(null); // Start with all sections collapsed

  const getLayerInfo = () => {
    const layers = {
      security: {
        title: 'Security',
        icon: '🛡️',
        description: 'Technical security vulnerabilities and threats detected in the extension code and configuration.',
        color: '#3B82F6',
      },
      privacy: {
        title: 'Privacy',
        icon: '🔒',
        description: 'Data collection, permissions, and potential data exfiltration risks.',
        color: '#8B5CF6',
      },
      governance: {
        title: 'Governance',
        icon: '📋',
        description: 'Policy compliance, behavioral consistency, and disclosure alignment.',
        color: '#10B981',
      },
    };
    return layers[layer] || layers.security;
  };

  const layerInfo = getLayerInfo();
  const displayScore = score === null ? 'Coming soon' : Math.round(score);
  const displayBand = band === 'NA' ? '' : band;

  const getBandColor = () => {
    if (score === null) return '#6B7280';
    switch (band) {
      case 'GOOD': return '#10B981';
      case 'WARN': return '#F59E0B';
      case 'BAD': return '#EF4444';
      default: return '#6B7280';
    }
  };

  const toggleSection = (section) => {
    setExpandedSection(expandedSection === section ? null : section);
  };

  return (
    <Dialog open={open} onOpenChange={onClose}>
      <DialogContent className="layer-modal-content">
        <DialogHeader>
          <DialogTitle className="layer-modal-title">
            <span className="title-icon">{layerInfo.icon}</span>
            <span className="title-text">{layerInfo.title} Details</span>
            <div className="title-status">
              <span className="title-score" style={{ color: getBandColor() }}>
                {score !== null ? `${displayScore}/100` : displayScore}
              </span>
              {displayBand && (
                <span className="title-band" style={{ color: getBandColor() }}>
                  {displayBand}
                </span>
              )}
            </div>
          </DialogTitle>
        </DialogHeader>

        <div className="layer-modal-body">
          {/* Layer Description */}
          <p className="layer-description">{layerInfo.description}</p>

          {/* Human-Friendly Layer Details */}
          {layerDetails && layerDetails[layer] && (
            <div className="human-friendly-section">
              <div className="human-summary">
                <span className="summary-text">{layerDetails[layer].one_liner}</span>
              </div>
              
              {/* Key Points */}
              {layerDetails[layer].key_points && layerDetails[layer].key_points.filter(point => point && point.trim()).length > 0 && (
                <div className="key-points">
                  <h4 className="key-points-title">Key Findings</h4>
                  <ul className="key-points-list">
                    {layerDetails[layer].key_points
                      .filter(point => point && point.trim())
                      .map((point, idx) => (
                        <li key={idx} className="key-point-item">
                          <span className="bullet">•</span>
                          <span className="point-text">{point}</span>
                        </li>
                      ))
                    }
                  </ul>
                </div>
              )}

              {/* What to Watch */}
              {layerDetails[layer].what_to_watch && layerDetails[layer].what_to_watch.filter(item => item && item.trim()).length > 0 && (
                <div className="what-to-watch">
                  <h4 className="what-to-watch-title">What to Watch</h4>
                  <ul className="what-to-watch-list">
                    {layerDetails[layer].what_to_watch
                      .filter(item => item && item.trim())
                      .map((item, idx) => (
                        <li key={idx} className="watch-item">
                          <span className="bullet">⚠</span>
                          <span className="watch-text">{item}</span>
                        </li>
                      ))
                    }
                  </ul>
                </div>
              )}
            </div>
          )}

          {/* Key Findings / Gates / Reasons */}
          {(keyFindings.length > 0 || gateResults.length > 0 || layerReasons.length > 0) && (
            <div className="modal-section">
              <div 
                className="section-header"
                onClick={() => toggleSection('findings')}
              >
                <h3 className="section-title">
                  <span className="section-icon">🔍</span>
                  Analysis Notes ({keyFindings.length + gateResults.length + layerReasons.length})
                </h3>
                <span className={`expand-icon ${expandedSection === 'findings' ? 'expanded' : ''}`}>
                  ›
                </span>
              </div>
              {expandedSection === 'findings' && (
                <div className="section-content">
                  <ul className="findings-list">
                    {/* Hard Gates First */}
                    {gateResults.map((gate, idx) => {
                      const severity = gate.decision === 'BLOCK' ? 'high' : 'medium';
                      return (
                        <li key={`gate-${idx}`} className="finding-item">
                          <span className={`finding-severity severity-${severity}`}>
                            {gate.decision === 'BLOCK' ? 'CRITICAL' : 'WARN'}
                          </span>
                          <span className="finding-text">{gate.gate_id}: {gate.reasons?.join(', ') || 'Triggered'}</span>
                        </li>
                      );
                    })}
                    {/* Then Key Findings */}
                    {keyFindings.map((finding, idx) => (
                      <li key={`finding-${idx}`} className="finding-item">
                        <span className={`finding-severity severity-${finding.severity}`}>
                          {finding.severity.toUpperCase()}
                        </span>
                        <span className="finding-text">{finding.title}</span>
                        {finding.evidenceIds && finding.evidenceIds.length > 0 && onViewEvidence && (
                          <button
                            className="view-evidence-btn"
                            onClick={(e) => {
                              e.stopPropagation();
                              onViewEvidence(finding.evidenceIds);
                            }}
                          >
                            View Evidence
                          </button>
                        )}
                      </li>
                    ))}
                    {/* Then Layer Reasons */}
                    {layerReasons.map((reason, idx) => (
                      <li key={`reason-${idx}`} className="finding-item">
                        <span className="finding-severity severity-low">INFO</span>
                        <span className="finding-text">{reason}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          )}

          {/* Factors */}
          {factors.length > 0 && (
            <div className="modal-section">
              <div 
                className="section-header"
                onClick={() => toggleSection('factors')}
              >
                <h3 className="section-title">
                  <span className="section-icon">📊</span>
                  Risk Factors ({factors.length})
                </h3>
                <span className={`expand-icon ${expandedSection === 'factors' ? 'expanded' : ''}`}>
                  ›
                </span>
              </div>
              {expandedSection === 'factors' && (
                <div className="section-content">
                  <FactorBars
                    title=""
                    factors={factors}
                    onViewEvidence={onViewEvidence}
                  />
                </div>
              )}
            </div>
          )}

          {/* Security Modal: Powerful Permissions */}
          {layer === 'security' && powerfulPermissions.length > 0 && (
            <div className="modal-section">
              <div 
                className="section-header"
                onClick={() => toggleSection('permissions')}
              >
                <h3 className="section-title">
                  <span className="section-icon">🔑</span>
                  Powerful Permissions ({powerfulPermissions.length})
                </h3>
                <span className={`expand-icon ${expandedSection === 'permissions' ? 'expanded' : ''}`}>
                  ›
                </span>
              </div>
              {expandedSection === 'permissions' && (
                <div className="section-content">
                  <div className="permissions-chips">
                    {powerfulPermissions.map((perm, idx) => (
                      <span key={idx} className="permission-chip risk-high">
                        {perm}
                      </span>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* Privacy Modal: Full Permissions */}
          {layer === 'privacy' && permissions && (
            <div className="modal-section">
              <div 
                className="section-header"
                onClick={() => toggleSection('permissions')}
              >
                <h3 className="section-title">
                  <span className="section-icon">🔑</span>
                  Permissions
                </h3>
                <span className={`expand-icon ${expandedSection === 'permissions' ? 'expanded' : ''}`}>
                  ›
                </span>
              </div>
              {expandedSection === 'permissions' && (
                <div className="section-content">
                  <PermissionsPanel permissions={permissions} />
                </div>
              )}
            </div>
          )}

          {/* Governance Modal: Policy Details */}
          {layer === 'governance' && (
            <div className="modal-section">
              <div 
                className="section-header"
                onClick={() => toggleSection('policy')}
              >
                <h3 className="section-title">
                  <span className="section-icon">📜</span>
                  Policy & Compliance
                </h3>
                <span className={`expand-icon ${expandedSection === 'policy' ? 'expanded' : ''}`}>
                  ›
                </span>
              </div>
              {expandedSection === 'policy' && (
                <div className="section-content">
                  <p className="policy-text">
                    This section shows policy compliance details, including Terms of Service violations,
                    purpose mismatches, and disclosure alignment issues.
                  </p>
                </div>
              )}
            </div>
          )}
        </div>
      </DialogContent>
    </Dialog>
  );
};

export default LayerModal;

