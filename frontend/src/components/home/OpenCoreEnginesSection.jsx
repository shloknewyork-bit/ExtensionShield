import React, { useRef, useState, useEffect } from "react";
import { Link } from "react-router-dom";
import { motion, useScroll, useTransform, useInView, useMotionValueEvent } from "framer-motion";
import { Shield, Eye, Scale, Users, CheckCircle2 } from "lucide-react";
import "./OpenCoreEnginesSection.scss";

const SCORE_WEIGHTS = { security: 40, privacy: 35, compliance: 25 };

const TRUST_CHIPS = [
  "Open-core engine",
  "Deterministic rules",
  "Evidence attached",
  "Reproducible scans",
  "Policy-ready controls",
];

const STEPS = [
  { id: "security", label: "Security", Icon: Shield, desc: "Permissions & code scanned for risks.", weight: "40%", variant: "security" },
  { id: "privacy", label: "Privacy", Icon: Eye, desc: "Data handling and tracking checked.", weight: "35%", variant: "privacy" },
  { id: "governance", label: "Governance", Icon: Scale, desc: "Compliance and policy signals.", weight: "25%", variant: "governance" },
  { id: "community", label: "Community", Icon: Users, desc: "Reports and community signals.", weight: "", variant: "community" },
  { id: "results", label: "Results", Icon: CheckCircle2, desc: "Single score with full evidence.", weight: "", variant: "results" },
];

const OpenCoreEnginesSection = () => {
  const sectionRef = useRef(null);
  const flowRef = useRef(null);
  const isInView = useInView(sectionRef, { once: false, amount: 0.1 });
  const [reduced, setReduced] = useState(false);
  const [activeStep, setActiveStep] = useState(-1);

  useEffect(() => {
    const mq = window.matchMedia("(prefers-reduced-motion: reduce)");
    setReduced(mq.matches);
    const h = () => setReduced(mq.matches);
    mq.addEventListener("change", h);
    return () => mq.removeEventListener("change", h);
  }, []);

  const { scrollYProgress } = useScroll({
    target: flowRef,
    offset: ["start 0.85", "end 0.4"],
  });

  useMotionValueEvent(scrollYProgress, "change", (v) => {
    if (v < 0.12) setActiveStep(0);
    else if (v < 0.32) setActiveStep(1);
    else if (v < 0.52) setActiveStep(2);
    else if (v < 0.72) setActiveStep(3);
    else setActiveStep(4);
  });

  const line1 = useTransform(scrollYProgress, [0.02, 0.2], [0, 1]);
  const line2 = useTransform(scrollYProgress, [0.22, 0.4], [0, 1]);
  const line3 = useTransform(scrollYProgress, [0.42, 0.6], [0, 1]);
  const line4 = useTransform(scrollYProgress, [0.62, 0.8], [0, 1]);

  const node0 = useTransform(scrollYProgress, [0, 0.1], [0, 1]);
  const node1 = useTransform(scrollYProgress, [0.1, 0.22], [0, 1]);
  const node2 = useTransform(scrollYProgress, [0.2, 0.32], [0, 1]);
  const node3 = useTransform(scrollYProgress, [0.3, 0.42], [0, 1]);
  const node4 = useTransform(scrollYProgress, [0.5, 0.62], [0, 1]);
  const node5 = useTransform(scrollYProgress, [0.7, 0.85], [0, 1]);
  const nodeOpacities = [node0, node1, node2, node3, node4, node5];

  return (
    <section
      id="how-we-score"
      ref={sectionRef}
      className="open-core-engines-section"
      aria-labelledby="open-core-heading"
    >
      <div className="open-core-engines-inner">
        <div className="open-core-streamlined">
          {/* Copy block: Open-core engines, How we score, chips, paragraph, CTAs */}
          <motion.div
            className="open-core-left"
            initial={{ opacity: 0, y: 12 }}
            animate={isInView ? { opacity: 1, y: 0 } : {}}
            transition={{ duration: reduced ? 0.2 : 0.28, ease: [0.25, 0.46, 0.45, 0.94] }}
          >
            <h2 id="open-core-heading" className="open-core-title">
              Built on open source + ExtensionShield rulepacks.
              <br />
              Every result links to evidence.
            </h2>
            <div className="open-core-chips">
              <div className="open-core-chips-row">
                {TRUST_CHIPS.slice(0, 3).map((chip) => (
                  <span key={chip} className="open-core-chip">
                    {chip}
                  </span>
                ))}
              </div>
              <div className="open-core-chips-row">
                {TRUST_CHIPS.slice(3, 5).map((chip) => (
                  <span key={chip} className="open-core-chip">
                    {chip}
                  </span>
                ))}
              </div>
            </div>
            <p className="open-core-weights-note">
              Security, Privacy, and Governance run as independent pipelines; we combine them with transparent weights and show the exact signals behind each score.
            </p>
            <p className="open-core-weights-line">
              Security {SCORE_WEIGHTS.security}% · Privacy {SCORE_WEIGHTS.privacy}% · Governance {SCORE_WEIGHTS.compliance}% · Community adds context + alerts
            </p>
            <div className="open-core-ctas">
              <Link to="/open-source" className="open-core-cta">
                Open source
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <path d="M5 12h14M12 5l7 7-7 7" />
                </svg>
              </Link>
              <Link to="/research/methodology" className="open-core-cta">
                Methodology
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <path d="M5 12h14M12 5l7 7-7 7" />
                </svg>
              </Link>
            </div>
          </motion.div>

          {/* Single workflow-style flow: green connectors + step nodes (replaces journey) */}
          <div className="open-core-flow" ref={flowRef}>
            <div className="open-core-flow-track">
              {STEPS.map((step, i) => (
                <React.Fragment key={step.id}>
                  <motion.div
                    className={`open-core-flow-node ${activeStep === i ? "workflow-node--active" : ""}`}
                    style={{ opacity: reduced ? 1 : nodeOpacities[i], scale: reduced ? 1 : nodeOpacities[i] }}
                  >
                    <div className={`workflow-node-box workflow-node-card--${step.variant} open-core-flow-card`}>
                      <step.Icon size={22} strokeWidth={2} aria-hidden />
                      <div className="open-core-flow-card-text">
                        <span className="open-core-flow-label">
                          {step.label}
                          {step.weight && <span className="workflow-node-weight">{step.weight}</span>}
                        </span>
                        <span className="open-core-flow-desc">{step.desc}</span>
                      </div>
                    </div>
                  </motion.div>
                  {i < STEPS.length - 1 && (
                    <div
                      className={`workflow-connector workflow-connector-v workflow-connector-green workflow-connector-tall${activeStep > i ? " workflow-connector-active" : ""}`}
                    >
                      <svg viewBox="0 0 12 60" preserveAspectRatio="xMidYMid meet" aria-hidden>
                        <motion.path
                          d="M6 0 L6 20 M6 40 L6 60"
                          fill="none"
                          strokeWidth="1.5"
                          strokeLinecap="round"
                          className="workflow-line-green"
                          style={{ pathLength: reduced ? 1 : [line1, line2, line3, line4][i] }}
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
            <motion.p
              className="open-core-workflow-more"
              style={{ opacity: reduced ? 1 : nodeOpacities[4] }}
            >
              <Link to="/research/methodology">View more on methodology page →</Link>
            </motion.p>
          </div>
        </div>
      </div>
    </section>
  );
};

export default OpenCoreEnginesSection;
