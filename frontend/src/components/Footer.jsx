import React from "react";
import { Link } from "react-router-dom";
import { footerConfig } from "../nav/navigation";
import ShieldLogo from "./ShieldLogo";
import { AUTH_ENABLED } from "../utils/featureFlags";
import "./Footer.scss";

const Footer = () => {
  const groups = footerConfig.linkGroups;

  return (
    <footer className="app-footer" role="contentinfo">
      <div className="app-footer__inner">
        <div className="app-footer__grid">
          {/* Left column: brand + disclaimer */}
          <div className="app-footer__brand-col">
            <Link to="/" className="app-footer__brand" aria-label="ExtensionShield home">
              <div className="app-footer__logo" aria-hidden="true">
                <ShieldLogo size={40} />
              </div>
              <span className="app-footer__name">ExtensionShield</span>
            </Link>
            {footerConfig.tagline && (
              <p className="app-footer__tagline">{footerConfig.tagline}</p>
            )}
            <p className="app-footer__disclaimer">{footerConfig.disclaimer}</p>
            {footerConfig.brandClarification && (
              <p className="app-footer__clarification">{footerConfig.brandClarification}</p>
            )}
          </div>

          {/* Right column: link groups */}
          <div className="app-footer__links-col">
            <div className="app-footer__groups">
              {groups.map((group, idx) => (
                <div key={idx} className="app-footer__group">
                  <span className="app-footer__group-heading">{group.heading}</span>
                  <ul className="app-footer__list" aria-label={group.heading}>
                    {group.links.map((link, i) => (
                      <li key={i}>
                        {link.external ? (
                          <a
                            href={link.href}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="app-footer__link"
                          >
                            {link.label}
                          </a>
                        ) : (
                          <Link to={link.path} className="app-footer__link">
                            {link.label}
                          </Link>
                        )}
                      </li>
                    ))}
                  </ul>
                </div>
              ))}
            </div>
          </div>
        </div>

        {!AUTH_ENABLED && (
          <div className="app-footer__cloud-cta">
            <p>
              Want saved history, team monitoring, and community reviews?{" "}
              <a href="https://extensionshield.com" target="_blank" rel="noopener noreferrer">
                Try ExtensionShield Cloud
              </a>
            </p>
          </div>
        )}

        {/* Bottom bar: optional accent line */}
        <div className="app-footer__bottom" aria-hidden="true">
          <div className="app-footer__accent-line" />
          <p className="app-footer__copy">
            © {new Date().getFullYear()} ExtensionShield. Open source extension security.
          </p>
        </div>
      </div>
    </footer>
  );
};

export default Footer;
