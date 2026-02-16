import React, { useId } from "react";
import "./ShieldLogo.scss";

/**
 * ShieldLogo Component
 * Animated shield logo for ExtensionShield - minimalist, trust-focused design
 * with subtle pulse animation similar to Railway's logo.
 * Uses unique IDs per instance to avoid Safari/WebKit ID-clash rendering issues.
 * No SVG filter on the shield path (filter can cause white/invisible logo in Safari).
 */
const ShieldLogo = ({ size = 32, className = "" }) => {
  const id = useId().replace(/:/g, "-");
  const gradientId = `shieldGradient-${id}`;
  return (
    <div className={`shield-logo ${className}`} style={{ width: size, height: size }}>
      <svg
        viewBox="0 0 100 100"
        fill="none"
        xmlns="http://www.w3.org/2000/svg"
        className="shield-svg"
        aria-hidden="true"
      >
        <defs>
          {/* Gradient for shield - unique ID per instance for Safari */}
          <linearGradient id={gradientId} x1="0%" y1="0%" x2="0%" y2="100%">
            <stop offset="0%" stopColor="#22c55e" stopOpacity="0.9" />
            <stop offset="100%" stopColor="#16a34a" stopOpacity="0.9" />
          </linearGradient>
        </defs>
        
        {/* Shield shape - no filter (Safari can render filtered SVGs as white) */}
        <path
          d="M50 10 L75 20 L75 45 Q75 65 50 85 Q25 65 25 45 L25 20 Z"
          fill={`url(#${gradientId})`}
          stroke="rgba(34, 197, 94, 0.3)"
          strokeWidth="1.5"
          className="shield-main"
        />
        
        {/* Inner shield accent - checkmark for security/trust */}
        <path
          d="M40 45 L47 52 L60 38"
          stroke="white"
          strokeWidth="3"
          strokeLinecap="round"
          strokeLinejoin="round"
          fill="none"
          className="shield-check"
          opacity="0.95"
        />
        
        {/* Subtle inner glow */}
        <ellipse
          cx="50"
          cy="45"
          rx="15"
          ry="12"
          fill="rgba(255, 255, 255, 0.1)"
          className="shield-inner-glow"
        />
      </svg>
    </div>
  );
};

export default ShieldLogo;

