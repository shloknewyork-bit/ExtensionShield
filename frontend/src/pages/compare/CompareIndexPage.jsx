import React from "react";
import { Link, useNavigate } from "react-router-dom";
import SEOHead from "../../components/SEOHead";
import "./ComparePage.scss";

const CompareIndexPage = () => {
  const navigate = useNavigate();

  return (
    <>
      <SEOHead
        title="Best Chrome Extension Security Scanner | CRXcavator Alternatives"
        description="Compare the best chrome extension security scanner tools. ExtensionShield vs CRXcavator, CRXplorer, ExtensionAuditor. Chrome extension risk score tool with security, privacy, and governance."
        pathname="/compare"
        ogType="website"
      />

      <div className="compare-page">
        <div className="compare-container">
          <div className="compare-back-wrapper">
          <button type="button" className="compare-back" onClick={() => navigate(-1)}>
            ← Back
          </button>
          </div>

          <header className="compare-header">
            <h1>Best Chrome Extension Security Scanner</h1>
            <p>
              Compare chrome extension security scanners and extension risk score tools. See how ExtensionShield stacks up against CRXcavator, CRXplorer, and ExtensionAuditor — and why teams choose us for browser extension security audit and extension governance.
            </p>
          </header>

          <div className="compare-prose">
            <p>
              Choosing the right <strong>chrome extension security scanner</strong> or <strong>browser extension security scanner</strong> matters for security, privacy, and compliance. ExtensionShield provides a <strong>chrome extension risk score</strong> built on three layers (Security, Privacy, Governance), plus a <strong>chrome extension permissions checker</strong>, malware scanning, and <strong>audit chrome extension security</strong> reports — so you can <strong>check if a chrome extension is safe</strong> before installing.
            </p>

            <p>
              Looking for <strong>CRXcavator alternatives</strong>? CRXcavator is a legacy enterprise tool; ExtensionShield offers transparent scoring, SAST + VirusTotal, and extension governance. Below we compare ExtensionShield to other popular options.
            </p>
          </div>

          <div className="compare-links">
            <h3>ExtensionShield vs competitors</h3>
            <ul>
              <li><Link to="/compare/crxcavator">ExtensionShield vs CRXcavator</Link></li>
              <li><Link to="/compare/crxplorer">ExtensionShield vs CRXplorer</Link></li>
              <li><Link to="/compare/extension-auditor">ExtensionShield vs ExtensionAuditor</Link></li>
            </ul>
          </div>

          <div className="compare-cta">
            <Link to="/scan">Scan an extension with ExtensionShield →</Link>
          </div>
        </div>
      </div>
    </>
  );
};

export default CompareIndexPage;
