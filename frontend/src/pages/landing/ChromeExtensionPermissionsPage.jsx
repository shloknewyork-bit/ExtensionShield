import React from "react";
import { Link, useNavigate } from "react-router-dom";
import SEOHead from "../../components/SEOHead";
import "../compare/ComparePage.scss";

/**
 * Evergreen permissions hub: explain common permissions, red flags, how to review.
 * Route: /chrome-extension-permissions
 * Canonical target for "how to check chrome extension permissions" intent.
 */
const ChromeExtensionPermissionsPage = () => {
  const navigate = useNavigate();

  return (
    <>
      <SEOHead
        title="Chrome Extension Permissions Explained | What to Allow | ExtensionShield"
        description="Understand Chrome extension permissions: which are risky, red flags to watch, and how to review before you install. Plus a free scanner to check any extension."
        pathname="/chrome-extension-permissions"
        ogType="website"
      />
      <div className="compare-page">
        <div className="compare-container">
          <div className="compare-back-wrapper">
          <button type="button" className="compare-back" onClick={() => navigate(-1)}>
            ← Back
          </button>
          </div>
          <nav className="breadcrumb" aria-label="Breadcrumb">
            <Link to="/">Home</Link>
            <span aria-hidden>/</span>
            <Link to="/is-this-chrome-extension-safe">Guide</Link>
            <span aria-hidden>/</span>
            <span>Permissions</span>
          </nav>

          <header className="compare-header">
            <h1>Chrome extension permissions explained</h1>
            <p>
              Extensions declare what they can access in the Chrome Web Store and in the browser. Here’s what common permissions mean, which ones are red flags, and how to review them before you install.
            </p>
          </header>

          <div className="compare-prose">
            <h2>Common permissions and what they allow</h2>
            <ul>
              <li><strong>Read and change your data on all websites</strong> — The broadest access. The extension can read and modify pages you visit, including form data and content. Needed for ad blockers and productivity tools; also used by trackers and malware.</li>
              <li><strong>Read your browsing history</strong> — Can see which sites you’ve visited. Often used for analytics or “recommendations”; can be a privacy risk.</li>
              <li><strong>Manage your downloads</strong> — Can add, remove, or read downloaded files. Necessary for download managers; risky if the extension is malicious.</li>
              <li><strong>Access your tabs and browsing activity</strong> — Can see open tabs and sometimes tab content. Common in tab managers and note-taking extensions.</li>
              <li><strong>Read and change data you copy and paste</strong> — Clipboard access. Useful for clipboard managers; dangerous if the extension exfiltrates data.</li>
              <li><strong>Storage</strong> — Local storage and sometimes sync. Usually lower risk but can hold sensitive data.</li>
            </ul>

            <h2>Red flags when reviewing permissions</h2>
            <ul>
              <li>Request for <strong>all websites</strong> when the extension’s description only needs a few (e.g. a “price checker” that wants full page access).</li>
              <li>Combinations that enable data exfiltration: e.g. “read data on all sites” + “communicate with external servers” without a clear, limited purpose.</li>
              <li>Permissions that don’t match the stated feature (e.g. a simple icon pack asking for history or tabs).</li>
              <li>Vague or missing privacy policy when the extension accesses personal or sensitive data.</li>
            </ul>

            <h2>How to review before you install</h2>
            <ol style={{ marginLeft: "1.25rem", marginBottom: "1rem" }}>
              <li style={{ marginBottom: "0.5rem" }}>On the Chrome Web Store listing, scroll to <strong>Permissions</strong>. Expand the list and read each one.</li>
              <li style={{ marginBottom: "0.5rem" }}>Ask whether each permission is needed for the feature the extension claims. When in doubt, look for alternatives that request less.</li>
              <li style={{ marginBottom: "0.5rem" }}>Use a scanner like ExtensionShield to see not only permissions but also which domains the extension can contact, plus code-quality and threat signals. One report gives you evidence before you install.</li>
            </ol>

            <div className="compare-cta" style={{ marginTop: "1.5rem", marginBottom: "1.5rem" }}>
              <Link to="/scan">Scan an extension — see permissions and risk</Link>
            </div>
          </div>

          <div className="compare-links" style={{ marginTop: "2rem" }}>
            <h3>Related</h3>
            <ul>
              <li><Link to="/is-this-chrome-extension-safe">Is this Chrome extension safe?</Link></li>
              <li><Link to="/scan">Scan an extension</Link></li>
              <li><Link to="/research/methodology">How we score extensions</Link></li>
              <li><Link to="/glossary">Glossary: permissions and security terms</Link></li>
            </ul>
          </div>
        </div>
      </div>
    </>
  );
};

export default ChromeExtensionPermissionsPage;
