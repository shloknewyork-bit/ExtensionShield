import React from "react";
import { Link, useNavigate } from "react-router-dom";
import SEOHead from "../../components/SEOHead";
import "../compare/ComparePage.scss";

/**
 * SEO landing page: primary consumer intent — "chrome extension security scanner"
 * Route: /chrome-extension-security-scanner
 */
const ChromeExtensionSecurityScannerPage = () => {
  const navigate = useNavigate();

  return (
    <>
      <SEOHead
        title="Chrome Extension Security Scanner | Free Scan & Risk Score | ExtensionShield"
        description="Free Chrome extension scanner and security audit. Scan any extension for malware, risk score, permissions & threats in under 60 seconds. For developers: audit extensions before release."
        pathname="/chrome-extension-security-scanner"
        ogType="website"
        keywords="free extension scanner, Chrome extension security scanner, free extension audit, extension risk score, scan Chrome extension"
      />
      <div className="compare-page">
        <div className="compare-container">
          <div className="compare-back-wrapper">
          <button type="button" className="compare-back" onClick={() => navigate(-1)}>
            ← Back
          </button>
          </div>
          <header className="compare-header">
            <h1>Chrome Extension Security Scanner</h1>
            <p>
              Check if a Chrome extension is safe before you install. ExtensionShield scans extensions for malware, privacy risks, and compliance issues and gives you a clear risk score in under a minute.
            </p>
          </header>

          <div className="compare-prose">
            <p>
              A <strong>chrome extension security scanner</strong> helps you understand what an extension can access and whether it has been flagged for malicious behavior. ExtensionShield combines static code analysis (SAST), permission checks, and threat intelligence so you get one actionable <strong>extension risk score</strong> plus a breakdown of Security, Privacy, and Governance.
            </p>
            <p>
              Paste a Chrome Web Store URL — no install required. We analyze permissions, network access, obfuscation, and known threats so you can decide if an extension is safe to use.
            </p>
            <ul>
              <li>Free to use; no account required for a single scan</li>
              <li>Risk score 0–100 with Security, Privacy, and Compliance dimensions</li>
              <li>Transparent methodology; we document how we score</li>
              <li>Useful for consumers and teams evaluating extensions</li>
            </ul>
          </div>

          <div className="compare-cta">
            <Link to="/scan">Scan an extension now →</Link>
          </div>

          <div className="compare-links">
            <h3>Related</h3>
            <ul>
              <li><Link to="/research/methodology">How we score extensions</Link></li>
              <li><Link to="/enterprise">Enterprise extension security</Link></li>
              <li><Link to="/compare/crxcavator">CRXcavator alternative</Link></li>
            </ul>
          </div>
        </div>
      </div>
    </>
  );
};

export default ChromeExtensionSecurityScannerPage;
