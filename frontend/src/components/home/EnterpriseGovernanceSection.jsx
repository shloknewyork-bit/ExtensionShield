import React from "react";
import { Link } from "react-router-dom";
import { motion } from "framer-motion";
import {
  ListChecks,
  AlertTriangle,
  RefreshCw,
  Database,
  Send,
  Search,
  ShieldCheck,
  Activity,
  Sparkles,
} from "lucide-react";
import "./OpenCoreEnginesSection.scss";

const BULLETS = [
  { Icon: ListChecks, text: "Policy allow/deny — enforce which extensions users can install" },
  { Icon: AlertTriangle, text: "Risky permission alerts — get notified when high-risk permissions are requested" },
  { Icon: RefreshCw, text: "Update monitoring — track version and permission changes over time" },
  { Icon: Database, text: "API & export — integrate with SIEM, ticketing, and audit workflows" },
];

const POLICY_STEPS = [
  { label: "Request", key: "request", Icon: Send },
  { label: "Evaluate & report", key: "evaluate", Icon: Search },
  { label: "Approve / block", key: "approve", Icon: ShieldCheck },
  { label: "Monitor", key: "monitor", Icon: Activity },
];

/**
 * Enterprise governance section: "Extensions increase productivity — but only the right ones."
 * Two-column: left copy + bullets + CTAs, right policy flow (timeline-style like HowWeProtect).
 */
const EnterpriseGovernanceSection = ({ reducedMotion = false }) => {
  const [hoveredStep, setHoveredStep] = React.useState(null);

  return (
    <section
      className="enterprise-governance-section landing-separator"
      aria-labelledby="enterprise-governance-heading"
    >
      <div className="enterprise-governance-inner">
        <div className="enterprise-governance-grid">
          {/* Left: copy, bullets, CTAs */}
          <div className="enterprise-governance-copy">
            <motion.p
              className="enterprise-governance-eyebrow"
              initial={reducedMotion ? false : { opacity: 0, y: 8 }}
              whileInView={reducedMotion ? {} : { opacity: 1, y: 0 }}
              viewport={{ once: true, amount: 0.2 }}
              transition={{ duration: 0.35, ease: [0.22, 1, 0.36, 1] }}
            >
              For security teams
            </motion.p>
            <motion.h2
              id="enterprise-governance-heading"
              className="enterprise-governance-title"
              initial={reducedMotion ? false : { opacity: 0, y: 12 }}
              whileInView={reducedMotion ? {} : { opacity: 1, y: 0 }}
              viewport={{ once: true, amount: 0.15 }}
              transition={{ duration: 0.4, delay: 0.05, ease: [0.22, 1, 0.36, 1] }}
            >
              Extensions increase productivity — but only the right ones.
            </motion.h2>
            <motion.p
              className="enterprise-governance-subtext"
              initial={reducedMotion ? false : { opacity: 0, y: 8 }}
              whileInView={reducedMotion ? {} : { opacity: 1, y: 0 }}
              viewport={{ once: true, amount: 0.2 }}
              transition={{ duration: 0.35, delay: 0.1 }}
            >
              Enforce policy, catch risky permissions, and monitor updates before they become incidents.
            </motion.p>
            <ul className="enterprise-governance-bullets">
              {BULLETS.map((item, i) => (
                <motion.li
                  key={i}
                  className="enterprise-governance-bullet"
                  initial={reducedMotion ? false : { opacity: 0, x: -8 }}
                  whileInView={reducedMotion ? {} : { opacity: 1, x: 0 }}
                  viewport={{ once: true, amount: 0.2 }}
                  transition={{ duration: 0.35, delay: 0.08 + i * 0.04 }}
                >
                  <item.Icon className="enterprise-governance-bullet-icon" aria-hidden />
                  <span>{item.text}</span>
                </motion.li>
              ))}
            </ul>
            <motion.div
              className="enterprise-governance-ctas"
              initial={reducedMotion ? false : { opacity: 0, y: 8 }}
              whileInView={reducedMotion ? {} : { opacity: 1, y: 0 }}
              viewport={{ once: true, amount: 0.2 }}
              transition={{ duration: 0.4, delay: 0.2 }}
            >
              <Link to="/enterprise#demo" className="enterprise-governance-btn enterprise-governance-btn--primary">
                Request a demo
              </Link>
            </motion.div>
          </div>

          {/* Right: policy flow – same design as open-core-flow-track (icon + name only) */}
          <motion.div
            className="enterprise-governance-visual"
            initial={reducedMotion ? false : { opacity: 0, x: 16 }}
            whileInView={reducedMotion ? {} : { opacity: 1, x: 0 }}
            viewport={{ once: true, amount: 0.15 }}
            transition={{ duration: 0.45, delay: 0.1, ease: [0.22, 1, 0.36, 1] }}
          >
            <div className="enterprise-governance-flow-wrap">
              <div className="enterprise-audit-flow-wrap" aria-hidden="true">
                <div className="audit-flow-pass" />
                <p className="audit-flow-headline">
                  <Sparkles size={14} strokeWidth={2} aria-hidden />
                  <span>We make audit easier</span>
                </p>
                <div className="open-core-flow open-core-flow-track--audit">
                  <div className="open-core-flow-track" role="list" aria-label="Audit flow: request to monitor">
                  {POLICY_STEPS.map((step, i) => (
                    <React.Fragment key={step.key}>
                      <motion.div
                        className={`open-core-flow-node workflow-node--active${hoveredStep === i ? " open-core-flow-node--hovered" : ""}`}
                        initial={reducedMotion ? false : { opacity: 0, y: 8 }}
                        whileInView={reducedMotion ? {} : { opacity: 1, y: 0 }}
                        viewport={{ once: true, amount: 0.2 }}
                        transition={{ duration: 0.35, delay: 0.05 * i }}
                        onMouseEnter={() => setHoveredStep(i)}
                        onMouseLeave={() => setHoveredStep(null)}
                      >
                        <button
                          type="button"
                          className="workflow-node-box workflow-node-card workflow-node-card--governance open-core-flow-card"
                          aria-label={step.label}
                        >
                          <step.Icon size={22} strokeWidth={2} aria-hidden />
                          <span className="open-core-flow-label">{step.label}</span>
                        </button>
                      </motion.div>
                      {i < POLICY_STEPS.length - 1 && (
                        <div
                          className="workflow-connector workflow-connector-v workflow-connector-green workflow-connector-tall workflow-connector-active"
                          aria-hidden
                        >
                          <svg viewBox="0 0 12 60" preserveAspectRatio="xMidYMid meet">
                            <path
                              d="M6 0 L6 20 M6 40 L6 60"
                              fill="none"
                              strokeWidth="1.5"
                              strokeLinecap="round"
                              className="workflow-line-green"
                            />
                            <circle
                              className="workflow-connector-hole"
                              cx="6"
                              cy="30"
                              r="5"
                            />
                          </svg>
                        </div>
                      )}
                    </React.Fragment>
                  ))}
                </div>
                </div>
              </div>
            </div>
          </motion.div>
        </div>
      </div>
    </section>
  );
};

export default EnterpriseGovernanceSection;
