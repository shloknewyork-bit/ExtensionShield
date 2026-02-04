import React, { useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import realScanService from "../services/realScanService";
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

  return (
    <div className="enterprise-page">
      <div className="enterprise-bg">
        <div className="bg-gradient" />
        <div className="bg-grid" />
        <div className="bg-glow glow-1" />
        <div className="bg-glow glow-2" />
      </div>

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
            <h3>What you’ll get</h3>
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
            <h3>Tell us about your org</h3>

            <div className="form-grid">
              <div className="field">
                <label>Name</label>
                <input value={form.name} onChange={onChange("name")} placeholder="Jane Doe" autoComplete="name" />
              </div>
              <div className="field">
                <label>Work email</label>
                <input
                  value={form.email}
                  onChange={onChange("email")}
                  placeholder="jane@company.com"
                  autoComplete="email"
                  inputMode="email"
                />
              </div>
              <div className="field full">
                <label>Company</label>
                <input value={form.company} onChange={onChange("company")} placeholder="Company, Inc." autoComplete="organization" />
              </div>
              <div className="field full">
                <label>Notes (optional)</label>
                <textarea
                  value={form.notes}
                  onChange={onChange("notes")}
                  placeholder="Number of endpoints/users, any compliance needs, what you want to monitor…"
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
  );
};

export default EnterprisePage;


