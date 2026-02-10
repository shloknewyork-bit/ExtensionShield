import React, { useEffect, useState } from 'react';
import './RiskGauge.scss';

/**
 * RiskGauge - Animated circular gauge showing overall risk score
 * Inspired by Robinhood's clean, minimal design
 */
const RiskGauge = ({ 
  score = 0, 
  size = 200, 
  label = 'Overall Score',
  decision = 'ALLOW',
  showAnimation = true 
}) => {
  const [animatedScore, setAnimatedScore] = useState(0);
  
  // Animate score on mount
  useEffect(() => {
    if (!showAnimation) {
      setAnimatedScore(score);
      return;
    }
    
    const duration = 1000;
    const steps = 60;
    const increment = score / steps;
    let current = 0;
    
    const timer = setInterval(() => {
      current += increment;
      if (current >= score) {
        setAnimatedScore(score);
        clearInterval(timer);
      } else {
        setAnimatedScore(Math.round(current));
      }
    }, duration / steps);
    
    return () => clearInterval(timer);
  }, [score, showAnimation]);

  // Calculate colors based on score
  // Thresholds: Green (85-100), Yellow (60-84), Red (0-59)
  const getScoreColor = (value) => {
    if (value >= 85) return { main: '#10B981', glow: 'rgba(16, 185, 129, 0.3)' }; // Green
    if (value >= 60) return { main: '#F59E0B', glow: 'rgba(245, 158, 11, 0.3)' }; // Yellow
    if (value >= 30) return { main: '#F97316', glow: 'rgba(249, 115, 22, 0.3)' }; // Orange
    return { main: '#EF4444', glow: 'rgba(239, 68, 68, 0.3)' }; // Red
  };

  const getRiskLabel = (value) => {
    if (value >= 85) return 'Low Risk';
    if (value >= 60) return 'Medium Risk';
    if (value >= 30) return 'High Risk';
    return 'Critical Risk';
  };

  const getDecisionStyle = (dec) => {
    switch (dec) {
      case 'ALLOW': return 'decision-allow';
      case 'BLOCK': return 'decision-block';
      case 'NEEDS_REVIEW': return 'decision-review';
      default: return '';
    }
  };

  const colors = getScoreColor(animatedScore);
  const strokeWidth = 12;
  const radius = (size - strokeWidth) / 2;
  const circumference = 2 * Math.PI * radius;
  const progress = ((100 - animatedScore) / 100) * circumference;

  return (
    <div className="risk-gauge" style={{ width: size, height: size }}>
      <svg 
        width={size} 
        height={size} 
        viewBox={`0 0 ${size} ${size}`}
        className="gauge-svg"
      >
        {/* Background track */}
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          fill="none"
          stroke="rgba(255, 255, 255, 0.08)"
          strokeWidth={strokeWidth}
        />
        
        {/* Glow effect */}
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          fill="none"
          stroke={colors.glow}
          strokeWidth={strokeWidth + 8}
          strokeLinecap="round"
          strokeDasharray={circumference}
          strokeDashoffset={progress}
          transform={`rotate(-90 ${size / 2} ${size / 2})`}
          className="gauge-glow"
          style={{ filter: 'blur(8px)' }}
        />
        
        {/* Progress arc */}
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          fill="none"
          stroke={colors.main}
          strokeWidth={strokeWidth}
          strokeLinecap="round"
          strokeDasharray={circumference}
          strokeDashoffset={progress}
          transform={`rotate(-90 ${size / 2} ${size / 2})`}
          className="gauge-progress"
        />
      </svg>
      
      <div className="gauge-content">
        <div className="gauge-score" style={{ color: colors.main }}>
          {animatedScore}
        </div>
        <div className="gauge-label">{label}</div>
        <div className="gauge-risk-label" style={{ color: colors.main }}>
          {getRiskLabel(animatedScore)}
        </div>
        <div className={`gauge-decision ${getDecisionStyle(decision)}`}>
          {decision.replace('_', ' ')}
        </div>
      </div>
    </div>
  );
};

export default RiskGauge;

