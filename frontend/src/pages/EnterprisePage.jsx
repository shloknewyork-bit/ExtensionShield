import React, { useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import realScanService from "../services/realScanService";
import SEOHead from "../components/SEOHead";
import "./EnterprisePage.scss";

const EnterprisePage = () => {
  const navigate = useNavigate();
  const API_BASE_URL = import.meta.env.VITE_API_URL || "";

  const [form, setForm] = useState({
    name: "",
    email: "",
    company: "",
    notes: "",
  });

  const [submitState, setSubmitState] = useState("idle"); // idle | loading | success | error
  const [submitMessage, setSubmitMessage] = useState("");

  const isValid = useMemo(() => {
    return Boolean(form.name.trim() && form.email.trim() && form.company.trim());
  }, [form.name, form.email, form.company]);

  const onChange = (key) => (e) => setForm((prev) => ({ ...prev, [key]: e.target.value }));

  const onSubmit = async (e) => {
    e.preventDefault();
    if (!isValid || submitState === "loading") return;

    setSubmitState("loading");
    setSubmitMessage("");

    try {
      const res = await fetch(`${API_BASE_URL}/api/enterprise/pilot-request`, {
        method: "POST",
        headers: { "Content-Type": "application/json", ...realScanService.getUserHeaders() },
        body: JSON.stringify(form),
      });

      if (!res.ok) {
        const data = await res.json().catch(() => ({}));
        throw new Error(data.detail || "Failed to submit request");
      }

      setSubmitState("success");
      setSubmitMessage("Request received. We’ll reach out soon.");
      setForm({ name: "", email: "", company: "", notes: "" });
    } catch (err) {
      setSubmitState("error");
      setSubmitMessage(err?.message || "Failed to submit request");
    }
  };

  const faqSchema = {
    "@context": "https://schema.org",
    "@type": "FAQPage",
    "mainEntity": [
      {
        "@type": "Question",
        "name": "What is enterprise extension management?",
        "acceptedAnswer": {
          "@type": "Answer",
          "text": "Enterprise extension management allows IT and security teams to monitor, govern, and enforce policies for browser extensions used across their organization. This includes risk scoring, compliance monitoring, and automated alerting."
        }
      },
      {
        "@type": "Question",
        "name": "How does extension governance work?",
        "acceptedAnswer": {
          "@type": "Answer",
          "text": "Extension governance enables organizations to create allow/block lists, enforce security policies, and generate audit-ready reports. Administrators can monitor extension usage and receive alerts when risk levels change."
        }
      },
      {
        "@type": "Question",
        "name": "What compliance features are available?",
        "acceptedAnswer": {
          "@type": "Answer",
          "text": "ExtensionShield Enterprise provides policy packs for common compliance frameworks, audit-ready exports, and detailed reporting on extension security, privacy, and governance signals."
        }
      },
      {
        "@type": "Question",
        "name": "Can I monitor extensions automatically?",
        "acceptedAnswer": {
          "@type": "Answer",
          "text": "Yes! Enterprise plans include automatic monitoring and re-scanning when extensions are updated. You'll receive alerts when risk scores change or new security issues are detected."
        }
      }
    ]
  };

  return (
    <>
      <SEOHead
        title="Enterprise Extension Security & Governance Platform"
        description="Enterprise-grade Chrome extension security with monitoring, governance, and compliance. Policy enforcement, automated alerting, and audit-ready exports for IT and security teams."
        pathname="/enterprise"
        ogType="website"
        schema={faqSchema}
      />
      <div className="enterprise-page">
      <div className="enterprise-container">
        <div className="enterprise-header">
          <button className="enterprise-back" onClick={() => navigate(-1)}>
            <span className="arrow">←</span> Back
          </button>

          <h1>Request an Enterprise Pilot</h1>
          <p>
            Monitoring, alerting, governance, and audit-ready exports for teams. No self-serve checkout — we’ll set up a pilot with you.
          </p>
        </div>

        <div className="enterprise-grid">
          <div className="enterprise-card">
            <h2>What you’ll get</h2>
            <ul className="enterprise-features">
              <li>Monitoring & auto-rescan on updates</li>
              <li>Alerting when risk changes</li>
              <li>Policy packs + audit exports</li>
              <li>Org allow/block list governance</li>
              <li>
                SSO/RBAC <span className="coming-soon-tag">Coming soon</span>
              </li>
            </ul>
          </div>

          <form className="enterprise-form" onSubmit={onSubmit}>
            <h2>Tell us about your org</h2>

            <div className="form-grid">
              <div className="field">
                <label htmlFor="enterprise-name">Name</label>
                <input
                  id="enterprise-name"
                  value={form.name}
                  onChange={onChange("name")}
                  autoComplete="name"
                  aria-required="true"
                />
              </div>
              <div className="field">
                <label htmlFor="enterprise-email">Work email</label>
                <input
                  id="enterprise-email"
                  value={form.email}
                  onChange={onChange("email")}
                  autoComplete="email"
                  inputMode="email"
                  aria-required="true"
                />
              </div>
              <div className="field full">
                <label htmlFor="enterprise-company">Company</label>
                <input
                  id="enterprise-company"
                  value={form.company}
                  onChange={onChange("company")}
                  autoComplete="organization"
                  aria-required="true"
                />
              </div>
              <div className="field full">
                <label htmlFor="enterprise-notes">Notes (optional)</label>
                <textarea
                  id="enterprise-notes"
                  value={form.notes}
                  onChange={onChange("notes")}
                  rows={4}
                />
              </div>
            </div>

            {submitMessage && (
              <div className={`form-status ${submitState}`}>
                {submitMessage}
              </div>
            )}

            <button
              type="submit"
              className="enterprise-submit"
              disabled={!isValid || submitState === "loading"}
              title={!isValid ? "Please fill name, work email, and company" : ""}
              aria-busy={submitState === "loading"}
            >
              {submitState === "loading" ? "Submitting..." : "Request Enterprise Pilot"}
            </button>

            <div className="form-note">
              We don’t collect payment here. This just starts a conversation.
            </div>
          </form>
        </div>
      </div>
      </div>
    </>
  );
};

export default EnterprisePage;


