import React, { useEffect, useState, useMemo, useRef } from 'react';
import './RiskDial.scss';

/**
 * RiskDial - Circular gauge with radiating colored segments
 * Design: Central circle with colored tick marks radiating outward
 * Colors transition from green (low risk/high score) to red (high risk/low score)
 * 
 * Props:
 * - score: number (0-100) - Security score (higher = safer)
 * - band: "GOOD" | "WARN" | "BAD" | "NA" - Band classification
 * - label?: string - Optional label (default: "SAFETY SCORE")
 * - decision?: "ALLOW" | "WARN" | "BLOCK" | null - Decision badge
 * - size?: number - Diameter in pixels (default: 280)
 */
const RiskDial = ({ 
  score = 0, 
  band = 'NA',
  label = 'SAFETY SCORE',
  decision = null,
  size = 280
}) => {
  // Clamp score 0-100
  const clampedScore = Math.max(0, Math.min(100, score ?? 0));
  
  // Initialize to 0 for animation effect
  const [animatedScore, setAnimatedScore] = useState(0);
  
  // Track animation frame for cleanup
  const animationFrameRef = useRef(null);
  const isMountedRef = useRef(true);
  const currentAnimatedScoreRef = useRef(0);
  
  // Generate unique ID for SVG filters to avoid conflicts with multiple instances
  const uniqueId = useMemo(() => `dial-${Math.random().toString(36).substr(2, 9)}`, []);
  
  // Update ref when animatedScore changes
  useEffect(() => {
    currentAnimatedScoreRef.current = animatedScore;
  }, [animatedScore]);
  
  // Animate score on mount and when score changes
  useEffect(() => {
    isMountedRef.current = true;
    
    // Cancel any existing animation
    if (animationFrameRef.current) {
      cancelAnimationFrame(animationFrameRef.current);
      animationFrameRef.current = null;
    }
    
    const duration = 1000;
    const startTime = Date.now();
    const startScore = currentAnimatedScoreRef.current;
    
    const animate = () => {
      if (!isMountedRef.current) {
        return;
      }
      
      const elapsed = Date.now() - startTime;
      const progress = Math.min(elapsed / duration, 1);
      // Ease-out cubic
      const eased = 1 - Math.pow(1 - progress, 3);
      const newScore = startScore + (clampedScore - startScore) * eased;
      
      if (isMountedRef.current) {
        setAnimatedScore(newScore);
      }
      
      if (progress < 1 && isMountedRef.current) {
        animationFrameRef.current = requestAnimationFrame(animate);
      } else {
        // Ensure we end at the exact target score
        if (isMountedRef.current) {
          setAnimatedScore(clampedScore);
          currentAnimatedScoreRef.current = clampedScore;
        }
        animationFrameRef.current = null;
      }
    };
    
    // Start animation
    animationFrameRef.current = requestAnimationFrame(animate);
    
    // Cleanup function
    return () => {
      isMountedRef.current = false;
      if (animationFrameRef.current) {
        cancelAnimationFrame(animationFrameRef.current);
        animationFrameRef.current = null;
      }
    };
  }, [clampedScore]);

  // Calculate which tick the needle should point to
  // Score 100 = low risk (green, left side), Score 0 = high risk (red, right side)
  // We invert because higher score = safer = less risk
  const riskLevel = 100 - animatedScore; // 0 = safe, 100 = dangerous
  
  // Generate tick marks - 24 ticks around the top arc (from -120° to +120°)
  const ticks = useMemo(() => {
    const tickCount = 24;
    const startAngle = -120; // degrees from top (left side)
    const endAngle = 120; // degrees from top (right side)
    const angleSpan = endAngle - startAngle;
    
    return Array.from({ length: tickCount }, (_, i) => {
      const progress = i / (tickCount - 1); // 0 to 1
      const angle = startAngle + progress * angleSpan;
      
      // Color zones aligned with score-band thresholds:
      // Green: 85-100 (0-15% of risk dial)
      // Yellow: 60-84 (15-40% of risk dial)
      // Red: 0-59 (40-100% of risk dial)
      let color;
      if (progress < 0.15) {
        // Pure green zone (85-100 score)
        const t = progress / 0.15;
        color = interpolateColor('#22C55E', '#84CC16', t);
      } else if (progress < 0.40) {
        // Yellow zone (60-84 score)
        const t = (progress - 0.15) / 0.25;
        color = interpolateColor('#84CC16', '#EAB308', t);
      } else {
        // Red zone (0-59 score)
        const t = (progress - 0.40) / 0.60;
        color = interpolateColor('#F97316', '#EF4444', t);
      }
      
      return { angle, color, index: i };
    });
  }, []);

  // Calculate needle angle based on risk level (inverted score)
  const needleAngle = useMemo(() => {
    const startAngle = -120;
    const endAngle = 120;
    const angleSpan = endAngle - startAngle;
    return startAngle + (riskLevel / 100) * angleSpan;
  }, [riskLevel]);

  const displayScore = Math.round(animatedScore);
  
  // Shared helper: derive band from score using backend-aligned thresholds
  // Green: score >= 85 => GOOD (Low risk)
  // Yellow: 60 <= score < 85 => WARN (Medium risk)
  // Red: score < 60 => BAD (High risk)
  const getBandFromScore = (scoreValue) => {
    if (scoreValue == null) return 'NA';
    if (scoreValue >= 85) return 'GOOD';
    if (scoreValue >= 60) return 'WARN';
    return 'BAD';
  };

  // Prefer explicit band prop; if it's NA, derive from score
  const effectiveBand = band === 'NA' ? getBandFromScore(clampedScore) : band;

  // Get risk label based on band
  const getRiskLabel = () => {
    switch (effectiveBand) {
      case 'GOOD': return 'Low Risk';
      case 'WARN': return 'Medium Risk';
      case 'BAD':  return 'High Risk';
      default:     return 'N/A';
    }
  };

  // Band-driven color: use effectiveBand as source of truth for marker/needle
  const getBandColor = () => {
    switch (effectiveBand) {
      case 'GOOD': return '#22C55E'; // green
      case 'WARN': return '#EAB308'; // yellow/amber
      case 'BAD':  return '#EF4444'; // red
      default:     return '#6B7280'; // neutral for NA
    }
  };

  const center = size / 2;
  const outerRadius = size * 0.42;
  const innerRadius = size * 0.32;
  const tickLength = size * 0.08;
  const circleRadius = size * 0.28;

  return (
    <div className="risk-dial-v2" style={{ width: size, height: size }}>
      <svg 
        width={size} 
        height={size}
        viewBox={`0 0 ${size} ${size}`}
        className="dial-svg"
      >
        {/* Subtle outer glow */}
        <defs>
          <filter id={`${uniqueId}-glow`} x="-50%" y="-50%" width="200%" height="200%">
            <feGaussianBlur stdDeviation="2" result="blur"/>
            <feMerge>
              <feMergeNode in="blur"/>
              <feMergeNode in="SourceGraphic"/>
            </feMerge>
          </filter>
          <radialGradient id={`${uniqueId}-gradient`} cx="50%" cy="50%" r="50%">
            <stop offset="0%" stopColor="#1a1f2e" />
            <stop offset="70%" stopColor="#0f1219" />
            <stop offset="100%" stopColor="#0a0d12" />
          </radialGradient>
          <filter id={`${uniqueId}-shadow`} x="-50%" y="-50%" width="200%" height="200%">
            <feDropShadow dx="0" dy="4" stdDeviation="8" floodColor="rgba(0,0,0,0.5)"/>
          </filter>
        </defs>

        {/* Tick marks */}
        {ticks.map(({ angle, color, index }) => {
          const rad = (angle - 90) * (Math.PI / 180);
          const x1 = center + innerRadius * Math.cos(rad);
          const y1 = center + innerRadius * Math.sin(rad);
          const x2 = center + outerRadius * Math.cos(rad);
          const y2 = center + outerRadius * Math.sin(rad);
          
          // Determine if this tick should be "active" (lit up)
          const tickProgress = index / (ticks.length - 1);
          const riskProgress = riskLevel / 100;
          const isActive = tickProgress <= riskProgress;
          
          return (
            <line
              key={index}
              x1={x1}
              y1={y1}
              x2={x2}
              y2={y2}
              stroke={color}
              strokeWidth={size * 0.025}
              strokeLinecap="round"
              opacity={isActive ? 1 : 0.25}
              style={{ 
                filter: isActive ? `url(#${uniqueId}-glow)` : 'none',
                transition: 'opacity 0.3s ease'
              }}
            />
          );
        })}

        {/* Center circle - outer ring */}
        <circle
          cx={center}
          cy={center}
          r={circleRadius + 4}
          fill="none"
          stroke="rgba(255,255,255,0.1)"
          strokeWidth="2"
        />

        {/* Center circle - main */}
        <circle
          cx={center}
          cy={center}
          r={circleRadius}
          fill={`url(#${uniqueId}-gradient)`}
          filter={`url(#${uniqueId}-shadow)`}
        />

        {/* Needle indicator */}
        <g transform={`rotate(${needleAngle}, ${center}, ${center})`}>
          <circle
            cx={center}
            cy={center - innerRadius + size * 0.02}
            r={size * 0.02}
            fill={getBandColor()}
            style={{ filter: `url(#${uniqueId}-glow)` }}
          />
        </g>
      </svg>

      {/* Center content */}
      <div className="dial-center-content">
        <div className="dial-main-label">{label}</div>
        <div className="dial-score" style={{ color: getBandColor() }}>
          {score === null ? '--' : displayScore}
        </div>
        <div className="dial-risk-label" style={{ color: getBandColor() }}>
          {getRiskLabel()}
        </div>
      </div>

      {/* Low / High labels */}
      <div className="dial-range-labels">
        <span className="range-low">low</span>
        <span className="range-high">high</span>
      </div>

      {/* Decision badge */}
      {decision && (
        <div className={`dial-decision decision-${decision.toLowerCase()}`}>
          {decision === 'ALLOW' ? '✓ Safe' : decision === 'BLOCK' ? '✕ Block' : '⚡ Review'}
        </div>
      )}
    </div>
  );
};

// Helper function to interpolate between two hex colors
function interpolateColor(color1, color2, factor) {
  const hex = (x) => {
    const h = Math.round(x).toString(16);
    return h.length === 1 ? '0' + h : h;
  };
  
  const r1 = parseInt(color1.slice(1, 3), 16);
  const g1 = parseInt(color1.slice(3, 5), 16);
  const b1 = parseInt(color1.slice(5, 7), 16);
  
  const r2 = parseInt(color2.slice(1, 3), 16);
  const g2 = parseInt(color2.slice(3, 5), 16);
  const b2 = parseInt(color2.slice(5, 7), 16);
  
  const r = r1 + factor * (r2 - r1);
  const g = g1 + factor * (g2 - g1);
  const b = b1 + factor * (b2 - b1);
  
  return `#${hex(r)}${hex(g)}${hex(b)}`;
}

export default RiskDial;
