import React, { useState, useEffect, useRef, useCallback } from "react";
import { useNavigate } from "react-router-dom";
import "./HomePage.scss";

// Static configuration - defined outside component to prevent recreation
const BADGE_CONFIG = [
  { id: 0, icon: "👁️", label: "Keystroke Logging", status: "detected", side: "left" },
  { id: 1, icon: "🔐", label: "Password Theft", status: "clear", side: "left" },
  { id: 2, icon: "📤", label: "Data Exfiltration", status: "detected", side: "left" },
  { id: 3, icon: "📹", label: "Camera Access", status: "detected", side: "right" },
  { id: 4, icon: "🌍", label: "Foreign Servers", status: "clear", side: "right" },
  { id: 5, icon: "💳", label: "Banking Fraud", status: "detected", side: "right" },
];

const SCAN_STATUS_MESSAGES = [
  "Checking permissions...",
  "Analyzing JavaScript...",
  "Scanning for data exfiltration...",
  "Detecting keyloggers...",
  "Verifying API endpoints...",
];

const HomePage = () => {
  const navigate = useNavigate();
  const [isVisible, setIsVisible] = useState(false);
  const [scanInput, setScanInput] = useState("");
  const [scanProgress, setScanProgress] = useState(0);
  const [currentThreat, setCurrentThreat] = useState(0);
  const [badgePositions, setBadgePositions] = useState([]);
  const [revealedSections, setRevealedSections] = useState({});
  const [scanCount, setScanCount] = useState(0); // Start at 0 - honest default
  const containerRef = useRef(null);
  const animationRef = useRef(null);
  const badgesRef = useRef([]);

  // Scan counter - TODO: Replace with real API call to get actual count
  // When ready: fetch('/api/stats').then(data => setScanCount(data.totalScans))
  useEffect(() => {
    // TODO: Fetch real scan count from API
    // Example: fetch('/api/stats').then(res => res.json()).then(data => setScanCount(data.totalScans));
  }, []);

  // Scroll reveal observer
  useEffect(() => {
    const observer = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          if (entry.isIntersecting) {
            setRevealedSections((prev) => ({
              ...prev,
              [entry.target.id]: true,
            }));
          }
        });
      },
      { threshold: 0.15, rootMargin: "0px 0px -50px 0px" }
    );

    const sections = document.querySelectorAll(".reveal-section");
    sections.forEach((section) => observer.observe(section));

    return () => observer.disconnect();
  }, []);

  const scrollToProof = () => {
    document.getElementById("proof")?.scrollIntoView({ behavior: "smooth" });
  };

  // Initialize badge positions
  const initializeBadges = useCallback(() => {
    if (!containerRef.current) return;
    
    const container = containerRef.current.getBoundingClientRect();
    const phoneWidth = 300;
    const phoneHeight = 600;
    const badgeWidth = 150;
    const badgeHeight = 110;
    const padding = 20;
    
    // Calculate zones - left side and right side of phone
    const centerX = container.width / 2;
    const centerY = container.height / 2;
    const phoneLeft = centerX - phoneWidth / 2;
    const phoneRight = centerX + phoneWidth / 2;
    
    const initialPositions = BADGE_CONFIG.map((badge, index) => {
      let x, y;
      const isLeft = badge.side === "left";
      
      if (isLeft) {
        // Left side badges - spread vertically
        x = padding + Math.random() * (phoneLeft - badgeWidth - padding * 3);
        y = padding + (index % 3) * ((container.height - badgeHeight - padding * 2) / 3) + Math.random() * 40;
      } else {
        // Right side badges - spread vertically
        x = phoneRight + padding + Math.random() * (container.width - phoneRight - badgeWidth - padding * 2);
        y = padding + ((index - 3) % 3) * ((container.height - badgeHeight - padding * 2) / 3) + Math.random() * 40;
      }
      
      // Random velocity in all directions
      const speed = 0.3 + Math.random() * 0.4;
      const angle = Math.random() * Math.PI * 2;
      
      return {
        ...badge,
        x: Math.max(padding, Math.min(x, container.width - badgeWidth - padding)),
        y: Math.max(padding, Math.min(y, container.height - badgeHeight - padding)),
        vx: Math.cos(angle) * speed,
        vy: Math.sin(angle) * speed,
        width: badgeWidth,
        height: badgeHeight,
      };
    });
    
    setBadgePositions(initialPositions);
    badgesRef.current = initialPositions;
  }, []);

  // Physics animation loop
  const animate = useCallback(() => {
    if (!containerRef.current || badgesRef.current.length === 0) {
      animationRef.current = requestAnimationFrame(animate);
      return;
    }

    const container = containerRef.current.getBoundingClientRect();
    const padding = 15;
    const phoneWidth = 280;
    const phoneHeight = 580;
    const centerX = container.width / 2;
    const centerY = container.height / 2;
    
    // Phone exclusion zone
    const phoneZone = {
      left: centerX - phoneWidth / 2 - 30,
      right: centerX + phoneWidth / 2 + 30,
      top: centerY - phoneHeight / 2 - 20,
      bottom: centerY + phoneHeight / 2 + 20,
    };

    const newPositions = badgesRef.current.map((badge, i) => {
      let { x, y, vx, vy, width, height } = badge;
      
      // Update position
      x += vx;
      y += vy;
      
      // Boundary collision (container edges)
      if (x <= padding) {
        x = padding;
        vx = Math.abs(vx) * 0.9;
      }
      if (x >= container.width - width - padding) {
        x = container.width - width - padding;
        vx = -Math.abs(vx) * 0.9;
      }
      if (y <= padding) {
        y = padding;
        vy = Math.abs(vy) * 0.9;
      }
      if (y >= container.height - height - padding) {
        y = container.height - height - padding;
        vy = -Math.abs(vy) * 0.9;
      }
      
      // Phone exclusion zone collision
      const badgeCenterX = x + width / 2;
      const badgeCenterY = y + height / 2;
      
      if (badgeCenterX > phoneZone.left && badgeCenterX < phoneZone.right &&
          badgeCenterY > phoneZone.top && badgeCenterY < phoneZone.bottom) {
        // Push away from phone center
        const pushX = badgeCenterX < centerX ? -1 : 1;
        const pushY = badgeCenterY < centerY ? -1 : 1;
        vx = pushX * Math.abs(vx) * 1.2;
        vy = pushY * Math.abs(vy) * 1.2;
        x += pushX * 5;
        y += pushY * 5;
      }
      
      // Badge-to-badge collision
      badgesRef.current.forEach((other, j) => {
        if (i === j) return;
        
        const dx = (x + width / 2) - (other.x + other.width / 2);
        const dy = (y + height / 2) - (other.y + other.height / 2);
        const distance = Math.sqrt(dx * dx + dy * dy);
        const minDistance = (width + other.width) / 2 + 20;
        
        if (distance < minDistance && distance > 0) {
          // Collision detected - bounce apart
          const angle = Math.atan2(dy, dx);
          const overlap = minDistance - distance;
          
          // Separate badges
          x += Math.cos(angle) * overlap * 0.5;
          y += Math.sin(angle) * overlap * 0.5;
          
          // Bounce velocity
          vx += Math.cos(angle) * 0.3;
          vy += Math.sin(angle) * 0.3;
        }
      });
      
      // Add slight random drift for organic movement
      vx += (Math.random() - 0.5) * 0.02;
      vy += (Math.random() - 0.5) * 0.02;
      
      // Damping to prevent runaway speeds
      const maxSpeed = 1.2;
      const speed = Math.sqrt(vx * vx + vy * vy);
      if (speed > maxSpeed) {
        vx = (vx / speed) * maxSpeed;
        vy = (vy / speed) * maxSpeed;
      }
      
      // Minimum speed to keep things moving
      const minSpeed = 0.15;
      if (speed < minSpeed) {
        const angle = Math.random() * Math.PI * 2;
        vx = Math.cos(angle) * minSpeed;
        vy = Math.sin(angle) * minSpeed;
      }
      
      return { ...badge, x, y, vx, vy };
    });
    
    badgesRef.current = newPositions;
    setBadgePositions([...newPositions]);
    
    animationRef.current = requestAnimationFrame(animate);
  }, []);

  useEffect(() => {
    setIsVisible(true);
    
    // Animate scan progress
    const progressTimer = setInterval(() => {
      setScanProgress(prev => {
        if (prev >= 100) return 0;
        return prev + 1;
      });
    }, 50);

    // Cycle through threat checks
    const threatTimer = setInterval(() => {
      setCurrentThreat(prev => (prev + 1) % SCAN_STATUS_MESSAGES.length);
    }, 2000);
    
    // Initialize floating badges after a short delay
    const initTimer = setTimeout(() => {
      initializeBadges();
      animationRef.current = requestAnimationFrame(animate);
    }, 500);
    
    // Handle window resize
    const handleResize = () => {
      initializeBadges();
    };
    window.addEventListener('resize', handleResize);
    
    return () => {
      clearInterval(progressTimer);
      clearInterval(threatTimer);
      clearTimeout(initTimer);
      window.removeEventListener('resize', handleResize);
      if (animationRef.current) {
        cancelAnimationFrame(animationRef.current);
      }
    };
  }, [initializeBadges, animate]);

  const handleScan = () => {
    if (scanInput.trim()) {
      navigate('/scanner', { state: { prefillUrl: scanInput.trim() } });
    } else {
      navigate('/scanner');
    }
  };

  return (
    <div className="home-page">
      {/* Hero Section */}
      <section className="hero-section">
        {/* Background Effects */}
        <div className="hero-bg">
          <div className="bg-gradient" />
          <div className="bg-grid" />
          <div className="bg-glow glow-1" />
          <div className="bg-glow glow-2" />
          
          {/* Red Scanner/Radar Effect */}
          <div className="radar-scanner">
            <div className="radar-ring radar-ring-1" />
            <div className="radar-ring radar-ring-2" />
            <div className="radar-ring radar-ring-3" />
            <div className="radar-ring radar-ring-4" />
            <div className="radar-sweep" />
            <div className="radar-center" />
          </div>
        </div>

        {/* Hero Headline - Moves to top on mobile */}
        <div className={`hero-headline ${isVisible ? 'visible' : ''}`}>
          <h1 className="hero-title">
            Scan any extension for <span className="highlight">hidden threats</span>
          </h1>
          <p className="hero-subtitle">
            Don't trust reviews. Trust the code.
          </p>
        </div>

        <div 
          ref={containerRef}
          className={`hero-content ${isVisible ? 'visible' : ''}`}
        >
          {/* Floating Security Badges - Physics-based movement */}
          {badgePositions.map((badge) => (
            <div
              key={badge.id}
              className={`floating-badge physics-badge ${badge.status}`}
              style={{
                transform: `translate(${badge.x}px, ${badge.y}px)`,
              }}
            >
              <span className="badge-icon">{badge.icon}</span>
              <span className="badge-label">{badge.label}</span>
              <span className="badge-status">
                {badge.status === 'detected' ? 'DETECTED' : 'CLEAR'}
              </span>
            </div>
          ))}

          {/* Central Scanner Device */}
          <div className="scanner-device">
            <div className="device-frame">
              <div className="device-notch" />
              <div className="device-screen">
                {/* Scanner Header */}
                <div className="scanner-header">
                  <div className="scanner-status">
                    <span className="status-dot" />
                    <span>Live Scan</span>
                  </div>
                </div>

                {/* Scanner Visualization */}
                <div className="scanner-visual">
                  <div className="scan-rings">
                    <div className="ring ring-1" />
                    <div className="ring ring-2" />
                    <div className="ring ring-3" />
                  </div>
                  <div className="scan-center">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
                      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
                      <path d="M9 12l2 2 4-4" />
                    </svg>
                  </div>
                  <div className="scan-line" style={{ transform: `rotate(${scanProgress * 3.6}deg)` }} />
                </div>

                {/* Current Check */}
                <div className="scanner-status-text">
                  <span className="status-label">{SCAN_STATUS_MESSAGES[currentThreat]}</span>
                </div>

                {/* Threat Indicators */}
                <div className="scanner-threats">
                  <div className="threat-row">
                    <span className="threat-icon safe">✓</span>
                    <span className="threat-name">Permissions</span>
                  </div>
                  <div className="threat-row">
                    <span className="threat-icon safe">✓</span>
                    <span className="threat-name">Data Safety</span>
                  </div>
                  <div className="threat-row scanning">
                    <span className="threat-icon">◌</span>
                    <span className="threat-name">Code Analysis</span>
                  </div>
                </div>

                {/* Bottom Action */}
                <div className="scanner-action">
                  <div className="action-btn">
                    <span>View Full Report</span>
                  </div>
                </div>
              </div>
            </div>
          </div>

        </div>

        {/* Hero Actions - Search */}
        <div className={`hero-actions ${isVisible ? 'visible' : ''}`}>
          <div className="hero-search">
            <div className="search-container">
              <div className="search-icon">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <circle cx="11" cy="11" r="8" />
                  <path d="M21 21l-4.35-4.35" />
                </svg>
              </div>
              <input
                type="text"
                placeholder="Paste Chrome Web Store URL or Extension ID"
                value={scanInput}
                onChange={(e) => setScanInput(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && handleScan()}
              />
              <button className="search-btn" onClick={handleScan}>
                <span>Scan Now</span>
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <path d="M5 12h14M12 5l7 7-7 7" />
                </svg>
              </button>
            </div>
            <p className="search-hint">✓ No install. No signup. Results in 60 seconds.</p>
          </div>
        </div>

        {/* Stats Bar - Separate for flexible positioning */}
        <div className={`stats-bar ${isVisible ? 'visible' : ''}`}>
          <div className="stat-item">
            <span className="stat-value counter">
              {scanCount > 0 ? `${scanCount.toLocaleString()}+` : 'NEW'}
            </span>
            <span className="stat-label">Extensions Scanned</span>
          </div>
          <div className="stat-divider" />
          <div className="stat-item">
            <span className="stat-value">47+</span>
            <span className="stat-label">Security Rules</span>
          </div>
          <div className="stat-divider" />
          <div className="stat-item">
            <span className="stat-value">&lt;60s</span>
            <span className="stat-label">Scan Time</span>
          </div>
          <div className="stat-divider" />
          <div className="stat-item">
            <span className="stat-value live">
              <span className="live-dot" />
              LIVE
            </span>
            <span className="stat-label">Threat Intel</span>
          </div>
        </div>

        {/* Scroll Cue */}
        <button className={`scroll-cue ${isVisible ? 'visible' : ''}`} onClick={scrollToProof}>
          <span>See how scams happen</span>
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <path d="M12 5v14M5 12l7 7 7-7" />
          </svg>
        </button>
      </section>

      {/* Bridge Section - How trusted extensions turn risky */}
      <section 
        id="proof" 
        className={`bridge-section reveal-section ${revealedSections['proof'] ? 'revealed' : ''}`}
      >
        <div className="bridge-gradient-top" />
        <div className="bridge-container">
          <h2 className="bridge-title">How trusted extensions turn risky</h2>
          
          <div className="bridge-steps">
            <div className="bridge-step">
              <div className="step-number">1</div>
              <div className="step-icon trust">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
                  <path d="M11.049 2.927c.3-.921 1.603-.921 1.902 0l1.519 4.674a1 1 0 00.95.69h4.915c.969 0 1.371 1.24.588 1.81l-3.976 2.888a1 1 0 00-.363 1.118l1.518 4.674c.3.922-.755 1.688-1.538 1.118l-3.976-2.888a1 1 0 00-1.176 0l-3.976 2.888c-.783.57-1.838-.197-1.538-1.118l1.518-4.674a1 1 0 00-.363-1.118l-3.976-2.888c-.784-.57-.38-1.81.588-1.81h4.914a1 1 0 00.951-.69l1.519-4.674z" />
                </svg>
              </div>
              <h3>Earn trust</h3>
              <p>5-star ratings, millions of installs, verified badge.</p>
            </div>

            <div className="bridge-connector">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M5 12h14M12 5l7 7-7 7" />
              </svg>
            </div>

            <div className="bridge-step">
              <div className="step-number">2</div>
              <div className="step-icon update">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
                  <path d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-8l-4-4m0 0L8 8m4-4v12" />
                </svg>
              </div>
              <h3>Ship an update</h3>
              <p>Payload hidden in a routine "bug fix" release.</p>
            </div>

            <div className="bridge-connector">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M5 12h14M12 5l7 7-7 7" />
              </svg>
            </div>

            <div className="bridge-step">
              <div className="step-number">3</div>
              <div className="step-icon abuse">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
                  <path d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                </svg>
              </div>
              <h3>Abuse permissions</h3>
              <p>Data theft, ad injection, affiliate hijacking.</p>
            </div>
          </div>

          <p className="bridge-footer">
            Most scams don't start malicious — they become malicious after they're trusted.
          </p>
        </div>
      </section>

      {/* Trust Deception Showcase */}
      <section 
        id="deception" 
        className={`deception-section reveal-section ${revealedSections['deception'] ? 'revealed' : ''}`}
      >
        <div className="deception-container">
          <div className="deception-cards">
            {/* Card 1 - PDF Helper */}
            <div className="deception-card">
              <div className="card-trust-layer">
                <div className="ext-icon pdf">
                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
                    <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
                    <path d="M14 2v6h6" />
                    <path d="M10 9h4M10 13h4M10 17h2" />
                  </svg>
                </div>
                <h4 className="ext-name">PDF Helper Pro</h4>
                <div className="ext-rating">
                  <div className="stars">★★★★★</div>
                  <span className="rating-score">4.9</span>
                </div>
                <div className="ext-users">2M+ users</div>
                <div className="ext-verified">
                  <svg viewBox="0 0 24 24" fill="currentColor">
                    <path d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                  </svg>
                  <span>Verified</span>
                </div>
              </div>
              <div className="card-truth-layer">
                <div className="threat-indicator">
                  <span className="threat-dot" />
                  <span className="threat-label">DATA THEFT</span>
                </div>
              </div>
            </div>

            {/* Card 2 - Tab Manager */}
            <div className="deception-card">
              <div className="card-trust-layer">
                <div className="ext-icon tabs">
                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
                    <rect x="3" y="3" width="18" height="18" rx="2" />
                    <path d="M3 9h18M9 21V9" />
                  </svg>
                </div>
                <h4 className="ext-name">Tab Manager</h4>
                <div className="ext-rating">
                  <div className="stars">★★★★★</div>
                  <span className="rating-score">4.8</span>
                </div>
                <div className="ext-users">800K users</div>
                <div className="ext-verified">
                  <svg viewBox="0 0 24 24" fill="currentColor">
                    <path d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                  </svg>
                  <span>Verified</span>
                </div>
              </div>
              <div className="card-truth-layer">
                <div className="threat-indicator">
                  <span className="threat-dot" />
                  <span className="threat-label">AD INJECTION</span>
                </div>
              </div>
            </div>

            {/* Card 3 - Price Saver */}
            <div className="deception-card">
              <div className="card-trust-layer">
                <div className="ext-icon price">
                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
                    <path d="M12 1v22M17 5H9.5a3.5 3.5 0 0 0 0 7h5a3.5 3.5 0 0 1 0 7H6" />
                  </svg>
                </div>
                <h4 className="ext-name">Price Saver</h4>
                <div className="ext-rating">
                  <div className="stars">★★★★★</div>
                  <span className="rating-score">4.7</span>
                </div>
                <div className="ext-users">5M+ users</div>
                <div className="ext-verified">
                  <svg viewBox="0 0 24 24" fill="currentColor">
                    <path d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                  </svg>
                  <span>Verified</span>
                </div>
              </div>
              <div className="card-truth-layer">
                <div className="threat-indicator">
                  <span className="threat-dot" />
                  <span className="threat-label">HIJACKING</span>
                </div>
              </div>
            </div>
          </div>

          <p className="deception-footer">
            These all passed review. <span className="danger">None are safe.</span>
          </p>
        </div>
      </section>

      {/* Honey Case Study Section */}
      <section className="honey-case-study">
        <div className="case-study-container">
          {/* Header */}
          <div className="case-study-header">
            <span className="case-study-badge">CASE STUDY</span>
            <h2 className="case-study-title">
              The Honey Extension Scam
              <span className="subtitle">17 Million Users. $4 Billion Acquisition. One Big Lie.</span>
            </h2>
          </div>

          {/* Main Content Grid */}
          <div className="case-study-content">
            {/* Left: Honey Icon */}
            <div className="honey-icon-section">
              <div className="honey-icon-wrapper">
                {/* Animated rings */}
                <div className="honey-ring honey-ring-1" />
                <div className="honey-ring honey-ring-2" />
                <div className="honey-ring honey-ring-3" />
                
                {/* Honey Logo - Hexagon with honeycomb pattern */}
                <div className="honey-logo">
                  <svg viewBox="0 0 100 100" fill="none" xmlns="http://www.w3.org/2000/svg">
                    {/* Hexagon background */}
                    <path 
                      d="M50 5L93.3 27.5V72.5L50 95L6.7 72.5V27.5L50 5Z" 
                      fill="url(#honeyGradient)" 
                      stroke="url(#honeyStroke)"
                      strokeWidth="2"
                    />
                    {/* Honeycomb cells */}
                    <path d="M50 30L62 38V54L50 62L38 54V38L50 30Z" fill="rgba(255,255,255,0.15)" />
                    <path d="M35 45L47 53V69L35 77L23 69V53L35 45Z" fill="rgba(255,255,255,0.1)" />
                    <path d="M65 45L77 53V69L65 77L53 69V53L65 45Z" fill="rgba(255,255,255,0.1)" />
                    {/* Letter H */}
                    <text x="50" y="58" textAnchor="middle" fill="white" fontSize="28" fontWeight="bold" fontFamily="Arial">h</text>
                    <defs>
                      <linearGradient id="honeyGradient" x1="0%" y1="0%" x2="100%" y2="100%">
                        <stop offset="0%" stopColor="#FF9500" />
                        <stop offset="50%" stopColor="#FF6B00" />
                        <stop offset="100%" stopColor="#E85D04" />
                      </linearGradient>
                      <linearGradient id="honeyStroke" x1="0%" y1="0%" x2="100%" y2="100%">
                        <stop offset="0%" stopColor="#FFB347" />
                        <stop offset="100%" stopColor="#FF8C00" />
                      </linearGradient>
                    </defs>
                  </svg>
                </div>
                
                {/* Warning badge */}
                <div className="warning-badge">
                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" />
                    <line x1="12" y1="9" x2="12" y2="13" />
                    <line x1="12" y1="17" x2="12.01" y2="17" />
                  </svg>
                </div>
              </div>
              
              <div className="honey-stats">
                <div className="honey-stat">
                  <span className="stat-number">17M+</span>
                  <span className="stat-desc">Active Users</span>
                </div>
                <div className="honey-stat">
                  <span className="stat-number">$4B</span>
                  <span className="stat-desc">PayPal Paid</span>
                </div>
                <div className="honey-stat">
                  <span className="stat-number danger">$0</span>
                  <span className="stat-desc">Real Savings</span>
                </div>
              </div>
            </div>

            {/* Right: Scam Details */}
            <div className="scam-details">
              <div className="scam-intro">
                <p>
                  Promised savings. Delivered <strong>stolen commissions</strong> and <strong>worse deals</strong>.
                </p>
              </div>

              <div className="scam-points">
                <div className="scam-point">
                  <div className="point-icon theft">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <circle cx="12" cy="12" r="10" />
                      <path d="M12 8v4M12 16h.01" />
                    </svg>
                  </div>
                  <div className="point-content">
                    <h4>Affiliate Link Hijacking</h4>
                    <p>Silently overwrote creator affiliate codes. Creators got nothing.</p>
                  </div>
                </div>

                <div className="scam-point">
                  <div className="point-icon data">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z" />
                      <circle cx="12" cy="12" r="3" />
                    </svg>
                  </div>
                  <div className="point-content">
                    <h4>Shopping Surveillance</h4>
                    <p>Tracked every view, cart, and purchase. Sold data to retailers.</p>
                  </div>
                </div>

                <div className="scam-point">
                  <div className="point-icon fake">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <path d="M18 6L6 18M6 6l12 12" />
                    </svg>
                  </div>
                  <div className="point-content">
                    <h4>Fake "Best" Coupons</h4>
                    <p>Showed worse deals than publicly available. The animation? Theater.</p>
                  </div>
                </div>

                <div className="scam-point">
                  <div className="point-icon money">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <line x1="12" y1="1" x2="12" y2="23" />
                      <path d="M17 5H9.5a3.5 3.5 0 0 0 0 7h5a3.5 3.5 0 0 1 0 7H6" />
                    </svg>
                  </div>
                  <div className="point-content">
                    <h4>Retailer Kickbacks</h4>
                    <p>Paid to suppress better deals. You got Honey's best price, not yours.</p>
                  </div>
                </div>
              </div>

              <div className="scam-footer">
                <div className="exposed-by">
                  <span>Exposed by</span>
                  <strong>MegaLag</strong>
                  <span className="date">• December 2024</span>
                </div>
                <div className="verdict">
                  <span className="verdict-label">VERDICT</span>
                  <span className="verdict-value">DECEPTIVE PRACTICES</span>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Pricing Section */}
      <section className="pricing-section">
        <div className="pricing-header">
          <h2>Simple, Transparent Pricing</h2>
          <p>Start free. Upgrade when you need more. Cancel anytime.</p>
        </div>

        <div className="pricing-grid">
          {/* Free */}
          <div className="pricing-card">
            <div className="pricing-card-header">
              <h3>Free</h3>
              <p>Try it out</p>
            </div>
            <div className="pricing-amount">
              <span className="price">$0</span>
              <span className="credits">2 scans/mo</span>
            </div>
            <div className="price-per-scan">No credit card required</div>
            <ul className="pricing-features">
              <li>
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <path d="M20 6L9 17l-5-5" />
                </svg>
                <span>AI threat analysis</span>
              </li>
              <li>
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <path d="M20 6L9 17l-5-5" />
                </svg>
                <span>Full security reports</span>
              </li>
            </ul>
            <button className="pricing-btn">Get Started</button>
          </div>

          {/* Starter */}
          <div className="pricing-card">
            <div className="pricing-card-header">
              <h3>Starter</h3>
              <p>See what we can do</p>
            </div>
            <div className="pricing-amount">
              <span className="price">$3.99</span>
              <span className="credits">15 scans/mo</span>
            </div>
            <div className="price-per-scan">Less than a coffee</div>
            <ul className="pricing-features">
              <li>
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <path d="M20 6L9 17l-5-5" />
                </svg>
                <span>AI threat analysis</span>
              </li>
              <li>
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <path d="M20 6L9 17l-5-5" />
                </svg>
                <span>Export reports</span>
              </li>
              <li>
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <path d="M20 6L9 17l-5-5" />
                </svg>
                <span>Priority scanning</span>
              </li>
              <li>
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <path d="M20 6L9 17l-5-5" />
                </svg>
                <span>Email support</span>
              </li>
            </ul>
            <button className="pricing-btn">Get Starter</button>
          </div>

          {/* Pro - Popular */}
          <div className="pricing-card popular">
            <div className="popular-badge">BEST VALUE</div>
            <div className="pricing-card-header">
              <h3>Pro</h3>
              <p>Your security partner</p>
            </div>
            <div className="pricing-amount">
              <span className="price">$9.99</span>
              <span className="credits">50 scans/mo</span>
            </div>
            <div className="price-per-scan">We grow with you</div>
            <ul className="pricing-features">
              <li>
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <path d="M20 6L9 17l-5-5" />
                </svg>
                <span>Everything in Starter</span>
              </li>
              <li>
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <path d="M20 6L9 17l-5-5" />
                </svg>
                <span>API access</span>
              </li>
              <li>
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <path d="M20 6L9 17l-5-5" />
                </svg>
                <span>Bulk scan uploads</span>
              </li>
              <li>
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <path d="M20 6L9 17l-5-5" />
                </svg>
                <span>Safe extension recommendations</span>
              </li>
            </ul>
            <button className="pricing-btn popular-btn">Get Pro</button>
          </div>
        </div>

        {/* Overage Packs */}
        <div className="overage-section">
          <div className="overage-card">
            <div className="overage-icon">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
                <path d="M12 4v16m8-8H4" />
              </svg>
            </div>
            <div className="overage-content">
              <h4>Need more scans?</h4>
              <p>Add <strong>+25 scans</strong> anytime for just <strong>$2.99</strong></p>
            </div>
            <button className="overage-btn">Add Scans</button>
          </div>
        </div>

        {/* Enterprise CTA */}
        <div className="enterprise-cta">
          <div className="enterprise-cta-content">
            <div className="enterprise-icon">🏢</div>
            <div className="enterprise-text">
              <h4>Enterprise</h4>
              <p>Governance, Compliance <span className="addon-tag">ADD-ON</span>, SSO, and audit logs for teams.</p>
            </div>
          </div>
          <button className="enterprise-cta-btn">Contact Sales</button>
        </div>
      </section>

      {/* Footer */}
      <footer className="home-footer">
        <div className="footer-content">
          <div className="footer-brand">
            <span className="brand-project">PROJECT</span>
            <span className="brand-dot">•</span>
            <span className="brand-atlas">ATLAS</span>
          </div>
          <p className="footer-disclaimer">
            Security analysis tool for Chrome extensions. Reports are evidence-based 
            and do not constitute legal advice.
          </p>
          <div className="footer-links">
            <a href="#docs">Documentation</a>
            <a href="#api">API</a>
            <a href="#github">GitHub</a>
          </div>
        </div>
      </footer>
    </div>
  );
};

export default HomePage;
