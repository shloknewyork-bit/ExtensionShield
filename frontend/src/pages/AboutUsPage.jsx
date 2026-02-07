import React from "react";
import { Link } from "react-router-dom";
import { Helmet } from "react-helmet-async";
import stanImage from "../assets/stanzin.png";
import "./AboutUsPage.scss";

const AboutUsPage = () => {
  return (
    <>
      <Helmet>
        <title>About Us | ExtensionShield</title>
        <meta name="description" content="Learn about ExtensionShield's founder, Stanzin, and why this project was created to help users understand browser extension security." />
        <link rel="canonical" href="https://extensionshield.com/about" />
      </Helmet>

      <div className="about-us-page">
        <div className="about-us-content">
          <div className="about-header">
            <div className="profile-image-container">
              <img 
                src={stanImage} 
                alt="Stanzin - Founder of ExtensionShield"
                className="profile-image"
                onError={(e) => {
                  // Fallback to placeholder if image doesn't exist
                  e.target.style.display = 'none';
                  const placeholder = e.target.nextElementSibling;
                  if (placeholder) placeholder.style.display = 'flex';
                }}
                onLoad={(e) => {
                  // Ensure image is visible when loaded
                  e.target.style.display = 'block';
                  const placeholder = e.target.nextElementSibling;
                  if (placeholder) placeholder.style.display = 'none';
                }}
              />
              <div className="profile-placeholder">
                <span>ST</span>
              </div>
            </div>
            <h1>Stanzin</h1>
            <p className="founder-title">Founder & Engineer</p>
          </div>

          <div className="about-story">
            <div className="story-section">
              <h2>Why I Built This</h2>
              <p>
                I learned the fun way that "harmless" browser extensions sometimes mean: "I would like access to your browsing history, clipboard, and first-born child."
              </p>
              <p>
                One day I installed an extension that looked totally normal… until I noticed the permissions didn't match what it claimed to do. So I went looking for a simple answer to a simple question:
              </p>
              <p>
                <strong>Is this extension actually safe?</strong>
              </p>
              <p>
                What I found instead were tools that were either too technical, too vague, or confidently wrong in a way only the internet can be. I couldn't find something that combined security analysis + privacy risk + compliance into a clear verdict you can act on.
              </p>
              <p>
                So I built ExtensionShield.
              </p>
            </div>

            <div className="story-section">
              <h2>Background</h2>
              <p>
                I got my start through the <strong>Google Open Source program</strong> and found my passion for software development. I joined Drupal (<a href="https://www.drupal.org/u/stanzin" target="_blank" rel="noopener noreferrer">drupal.org/u/stanzin</a>), where I learned the value of transparency, community review, "show your work," and the occasional spicy-but-correct code review.
              </p>
              <p>
                Drupal's community is also genuinely fun—smart engineers, real collaboration, and a culture that makes you level up fast.
              </p>
              <p>
                Later, I joined Hanover Insurance, which is basically the opposite vibe: regulated environments where security, privacy, and compliance aren't optional—they're the job. That experience shaped ExtensionShield into what I wanted in the first place.
              </p>
              <p>
                ExtensionShield is partially open source, and you can see how we calculate everything to be transparent.
              </p>
            </div>

            <div className="video-placeholder">
              <p className="video-note">📹 Video coming soon</p>
            </div>
          </div>

          <div className="about-links">
            <Link to="/open-source" className="link-button">
              <span>View Open Source</span>
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M5 12h14M12 5l7 7-7 7" />
              </svg>
            </Link>
            <a 
              href="https://github.com/Stanzin7/ExtensionShield" 
              target="_blank" 
              rel="noopener noreferrer"
              className="link-button"
            >
              <span>GitHub</span>
              <svg viewBox="0 0 24 24" fill="currentColor">
                <path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z" />
              </svg>
            </a>
            <a 
              href="https://www.linkedin.com/in/stanzin-norzang7/" 
              target="_blank" 
              rel="noopener noreferrer"
              className="link-button"
            >
              <span>LinkedIn</span>
              <svg viewBox="0 0 24 24" fill="currentColor">
                <path d="M20.447 20.452h-3.554v-5.569c0-1.328-.027-3.037-1.852-3.037-1.853 0-2.136 1.445-2.136 2.939v5.667H9.351V9h3.414v1.561h.046c.477-.9 1.637-1.85 3.37-1.85 3.601 0 4.267 2.37 4.267 5.455v6.286zM5.337 7.433c-1.144 0-2.063-.926-2.063-2.065 0-1.138.92-2.063 2.063-2.063 1.14 0 2.064.925 2.064 2.063 0 1.139-.925 2.065-2.064 2.065zm1.782 13.019H3.555V9h3.564v11.452zM22.225 0H1.771C.792 0 0 .774 0 1.729v20.542C0 23.227.792 24 1.771 24h20.451C23.2 24 24 23.227 24 22.271V1.729C24 .774 23.2 0 22.222 0h.003z"/>
              </svg>
            </a>
            <a 
              href="mailto:support@extensionshield.com" 
              className="link-button"
            >
              <span>Email</span>
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z" />
                <polyline points="22,6 12,13 2,6" />
              </svg>
            </a>
          </div>
        </div>
      </div>
    </>
  );
};

export default AboutUsPage;

