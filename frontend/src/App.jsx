import React from "react";
import { BrowserRouter as Router, Routes, Route, NavLink } from "react-router-dom";
import DashboardPage from "./pages/DashboardPage";
import ScanHistoryPage from "./pages/ScanHistoryPage";
import SampleReportPage from "./pages/SampleReportPage";
import AnalysisPage from "./pages/AnalysisPage";
import SettingsPage from "./pages/SettingsPage";
import "./App.scss";

function App() {
  // Force dark theme
  React.useEffect(() => {
    document.documentElement.style.backgroundColor = '#141414';
    document.body.style.backgroundColor = '#141414';
    document.documentElement.classList.add('dark');
  }, []);

  return (
    <Router>
      <div className="app" style={{ backgroundColor: '#141414' }}>
        <header className="modern-header">
          <div className="header-content">
            <NavLink to="/" className="logo-link">
              <span className="logo-dot">PROJECT</span>
              <span className="logo-diamond">◆</span>
              <span className="logo-stop">ATLAS</span>
            </NavLink>

            <nav className="main-nav">
              <NavLink
                to="/"
                className={({ isActive }) => `nav-link ${isActive ? 'active' : ''}`}
                end
              >
                <span className="nav-text">Home</span>
              </NavLink>
              <NavLink
                to="/scan-history"
                className={({ isActive }) => `nav-link ${isActive ? 'active' : ''}`}
              >
                <span className="nav-text">Account Types</span>
              </NavLink>

              <NavLink
                to="/analysis"
                className={({ isActive }) => `nav-link ${isActive ? 'active' : ''}`}
              >
                <span className="nav-text">Blog</span>
              </NavLink>
            </nav>

            <div className="header-actions">
              <button className="action-btn" aria-label="Share">
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <line x1="22" y1="2" x2="11" y2="13"></line>
                  <polygon points="22 2 15 22 11 13 2 9 22 2"></polygon>
                </svg>
              </button>
              <button className="action-btn" aria-label="Chat">
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"></path>
                </svg>
              </button>
            </div>
          </div>
        </header>

        <main className="main-content">
          <Routes>
            <Route path="/" element={<DashboardPage />} />
            <Route path="/scan-history" element={<ScanHistoryPage />} />
            <Route path="/sample-report" element={<SampleReportPage />} />
            <Route path="/analysis" element={<AnalysisPage />} />
            <Route path="/settings" element={<SettingsPage />} />
          </Routes>
        </main>
      </div>
    </Router>
  );
}

export default App;
