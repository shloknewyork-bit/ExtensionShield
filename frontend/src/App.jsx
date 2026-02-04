import React from "react";
import { BrowserRouter as Router, Routes, Route, NavLink, useLocation } from "react-router-dom";
import { AuthProvider, useAuth } from "./context/AuthContext";
import { ScanProvider } from "./context/ScanContext";

// Pages
import HomePage from "./pages/HomePage";
import { ScannerPage, ScanProgressPage, ScanResultsPage, ScanResultsPageV2 } from "./pages/scanner";
import { ReportsPage, ReportDetailPage } from "./pages/reports";
import ScanHistoryPage from "./pages/ScanHistoryPage";
import SettingsPage from "./pages/SettingsPage";
import EnterprisePage from "./pages/EnterprisePage";

// Components
import SignInModal from "./components/SignInModal";
import ShieldLogo from "./components/ShieldLogo";
import "./App.scss";

function UserMenu() {
  const { user, signOut, isLoading } = useAuth();
  const [isMenuOpen, setIsMenuOpen] = React.useState(false);
  const menuRef = React.useRef(null);

  // Close menu when clicking outside
  React.useEffect(() => {
    const handleClickOutside = (event) => {
      if (menuRef.current && !menuRef.current.contains(event.target)) {
        setIsMenuOpen(false);
      }
    };

    document.addEventListener("mousedown", handleClickOutside);
    return () => document.removeEventListener("mousedown", handleClickOutside);
  }, []);

  const handleSignOut = async () => {
    setIsMenuOpen(false);
    await signOut();
  };

  const getInitials = (name) => {
    if (!name) return "U";
    return name
      .split(" ")
      .map((n) => n[0])
      .join("")
      .toUpperCase()
      .slice(0, 2);
  };

  const getProviderIcon = (provider) => {
    switch (provider) {
      case "google":
        return (
          <svg viewBox="0 0 24 24" className="provider-badge google">
            <path
              fill="#4285F4"
              d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"
            />
            <path
              fill="#34A853"
              d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"
            />
            <path
              fill="#FBBC05"
              d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z"
            />
            <path
              fill="#EA4335"
              d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"
            />
          </svg>
        );
      case "github":
        return (
          <svg viewBox="0 0 24 24" fill="currentColor" className="provider-badge github">
            <path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z" />
          </svg>
        );
      default:
        return null;
    }
  };

  return (
    <div className="user-menu-container" ref={menuRef}>
      <button
        className="user-menu-trigger"
        onClick={() => setIsMenuOpen(!isMenuOpen)}
        disabled={isLoading}
      >
        {user.avatar ? (
          <img src={user.avatar} alt={user.name} className="user-avatar" />
        ) : (
          <div className="user-avatar-fallback">{getInitials(user.name)}</div>
        )}
        <span className="user-name">{user.name?.split(" ")[0]}</span>
        <svg
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          strokeWidth="2"
          className={`menu-chevron ${isMenuOpen ? "open" : ""}`}
        >
          <path d="M6 9l6 6 6-6" />
        </svg>
      </button>

      {isMenuOpen && (
        <div className="user-menu-dropdown">
          <div className="menu-header">
            <div className="menu-user-info">
              {user.avatar ? (
                <img src={user.avatar} alt={user.name} className="menu-avatar" />
              ) : (
                <div className="menu-avatar-fallback">{getInitials(user.name)}</div>
              )}
              <div className="menu-user-details">
                <span className="menu-user-name">{user.name}</span>
                <span className="menu-user-email">{user.email}</span>
              </div>
            </div>
            {user.provider && user.provider !== "email" && (
              <div className="menu-provider">
                {getProviderIcon(user.provider)}
                <span>Signed in with {user.provider === "google" ? "Google" : "GitHub"}</span>
              </div>
            )}
          </div>

          <div className="menu-divider" />

          <nav className="menu-nav">
            <NavLink to="/scanner" className="menu-item" onClick={() => setIsMenuOpen(false)}>
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
              </svg>
              <span>Scanner</span>
            </NavLink>
            <NavLink to="/history" className="menu-item" onClick={() => setIsMenuOpen(false)}>
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <circle cx="12" cy="12" r="10" />
                <path d="M12 6v6l4 2" />
              </svg>
              <span>Scan History</span>
            </NavLink>
            <NavLink to="/reports" className="menu-item" onClick={() => setIsMenuOpen(false)}>
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
                <path d="M14 2v6h6" />
                <path d="M16 13H8" />
                <path d="M16 17H8" />
                <path d="M10 9H8" />
              </svg>
              <span>Reports</span>
            </NavLink>
            <NavLink to="/settings" className="menu-item" onClick={() => setIsMenuOpen(false)}>
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <circle cx="12" cy="12" r="3" />
                <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z" />
              </svg>
              <span>Settings</span>
            </NavLink>
          </nav>

          <div className="menu-divider" />

          <button className="menu-item signout" onClick={handleSignOut}>
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4" />
              <polyline points="16 17 21 12 16 7" />
              <line x1="21" y1="12" x2="9" y2="12" />
            </svg>
            <span>Sign Out</span>
          </button>
        </div>
      )}
    </div>
  );
}

function InsightsMegamenu() {
  const location = useLocation();
  const [isOpen, setIsOpen] = React.useState(false);
  const menuRef = React.useRef(null);
  const isActive = location.pathname.startsWith("/reports") || location.pathname.startsWith("/history");

  React.useEffect(() => {
    const handleClickOutside = (event) => {
      if (menuRef.current && !menuRef.current.contains(event.target)) {
        setIsOpen(false);
      }
    };

    if (isOpen) {
      document.addEventListener("mousedown", handleClickOutside);
    }

    return () => document.removeEventListener("mousedown", handleClickOutside);
  }, [isOpen]);

  return (
    <div className="megamenu-container" ref={menuRef}>
      <button
        className={`nav-item megamenu-trigger ${isActive ? "active" : ""} ${isOpen ? "open" : ""}`}
        onClick={() => setIsOpen(!isOpen)}
      >
        Insights
        <svg width="12" height="12" viewBox="0 0 12 12" fill="none" stroke="currentColor" strokeWidth="2">
          <path d={isOpen ? "M3 9l3-3 3 3" : "M3 3l3 3 3-3"} />
        </svg>
      </button>

      {isOpen && (
        <div className="megamenu-dropdown">
          <div className="megamenu-grid">
            {/* Quick Actions */}
            <div className="megamenu-section">
              <h3 className="megamenu-section-title">Quick Access</h3>
              <NavLink to="/history" className="megamenu-item" onClick={() => setIsOpen(false)}>
                <span className="free-badge-top">Free</span>
                <div className="megamenu-icon">🕐</div>
                <div className="megamenu-content">
                  <div className="megamenu-label">
                    <span>Scan</span>
                    <span>History</span>
                  </div>
                  <div className="megamenu-desc">Browse all past scans</div>
                </div>
              </NavLink>
              <NavLink to="/reports" className="megamenu-item" onClick={() => setIsOpen(false)}>
                <span className="upgrade-badge-top">Enterprise</span>
                <div className="megamenu-icon">📋</div>
                <div className="megamenu-content">
                  <div className="megamenu-label">Security Reports</div>
                  <div className="megamenu-desc">View governance verdicts</div>
                </div>
              </NavLink>
            </div>

            {/* AI Recommendations */}
            <div className="megamenu-section">
              <h3 className="megamenu-section-title">
                <span className="ai-badge">✨ AI</span> Recommendations
              </h3>
              <NavLink to="/reports" className="megamenu-item ai-item" onClick={() => setIsOpen(false)}>
                <div className="megamenu-icon">👥</div>
                <div className="megamenu-content">
                  <div className="megamenu-label">Community Recommended</div>
                  <div className="megamenu-desc">Extensions trusted by users</div>
                </div>
              </NavLink>
              <div className="megamenu-item ai-item">
                <div className="megamenu-icon">🌱</div>
                <div className="megamenu-content">
                  <div className="megamenu-label">Open Source Impact</div>
                  <div className="megamenu-desc">20% back to quality software</div>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

function AppHeader() {
  const location = useLocation();
  const { user, isAuthenticated, openSignInModal, isLoading } = useAuth();
  const isHomePage = location.pathname === "/";

  return (
    <header className={`atlas-header ${isHomePage ? "transparent" : "solid"}`}>
      <div className="header-container">
        <NavLink to="/" className="header-logo">
          <ShieldLogo size={32} />
          <span className="logo-text">ExtensionShield</span>
        </NavLink>

        <nav className="header-nav">
          <NavLink to="/" className={({ isActive }) => `nav-item ${isActive ? "active" : ""}`} end>
            Home
          </NavLink>
          <NavLink
            to="/scanner"
            className={({ isActive }) => `nav-item ${isActive || location.pathname.startsWith("/scanner") ? "active" : ""}`}
          >
            Scanner
          </NavLink>
          <InsightsMegamenu />
        </nav>

        <div className="header-actions">
          {isLoading ? (
            <div className="auth-loading">
              <span className="loading-dot" />
              <span className="loading-dot" />
              <span className="loading-dot" />
            </div>
          ) : isAuthenticated && user ? (
            <UserMenu />
          ) : (
            <>
              <button className="action-signin" onClick={openSignInModal}>
                Sign In
              </button>
              <NavLink to="/scanner" className="action-signup">
                Get Started
              </NavLink>
            </>
          )}
        </div>
      </div>
    </header>
  );
}

function AppContent() {
  return (
    <div className="atlas-app">
      <AppHeader />
      <SignInModal />

      <main className="atlas-main">
        <Routes>
          {/* Home */}
          <Route path="/" element={<HomePage />} />
          
          {/* Scanner Routes */}
          <Route path="/scanner" element={<ScannerPage />} />
          <Route path="/scanner/progress/:scanId" element={<ScanProgressPage />} />
          <Route path="/scanner/results/:scanId" element={<ScanResultsPageV2 />} />
          {/* Legacy results page route (for direct access if needed) */}
          <Route path="/scanner/results-legacy/:scanId" element={<ScanResultsPage />} />
          
          {/* History */}
          <Route path="/history" element={<ScanHistoryPage />} />
          
          {/* Reports Routes */}
          <Route path="/reports" element={<ReportsPage />} />
          <Route path="/reports/:reportId" element={<ReportDetailPage />} />
          
          {/* Settings */}
          <Route path="/settings" element={<SettingsPage />} />

          {/* Enterprise */}
          <Route path="/enterprise" element={<EnterprisePage />} />
          
          {/* Legacy route redirects for backwards compatibility */}
          <Route path="/dashboard" element={<ScannerPage />} />
          <Route path="/scan-history" element={<ScanHistoryPage />} />
          <Route path="/sample-report" element={<ReportDetailPage />} />
          <Route path="/analysis" element={<ScannerPage />} />
        </Routes>
      </main>
    </div>
  );
}

function App() {
  // Force dark theme
  React.useEffect(() => {
    document.documentElement.style.backgroundColor = "#0a0f1a";
    document.body.style.backgroundColor = "#0a0f1a";
    document.documentElement.classList.add("dark");
  }, []);

  return (
    <Router>
      <AuthProvider>
        <ScanProvider>
          <AppContent />
        </ScanProvider>
      </AuthProvider>
    </Router>
  );
}

export default App;
