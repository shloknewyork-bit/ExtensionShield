import React, { useState, useEffect } from "react";
import { Helmet } from "react-helmet-async";
import { TrendChart, SourcesBox } from "../../components/benchmarks";
import "./BenchmarksPage.scss";

const BenchmarksPage = () => {
  const [trendsData, setTrendsData] = useState(null);
  const [benchmarksData, setBenchmarksData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [expandedCategory, setExpandedCategory] = useState(null);

  useEffect(() => {
    const loadData = async () => {
      try {
        const [trendsRes, benchmarksRes] = await Promise.all([
          fetch('/data/trends.json'),
          fetch('/data/benchmarks.json')
        ]);

        if (!trendsRes.ok || !benchmarksRes.ok) {
          throw new Error('Failed to load data');
        }

        const trends = await trendsRes.json();
        const benchmarks = await benchmarksRes.json();

        setTrendsData(trends);
        setBenchmarksData(benchmarks);
        setLoading(false);
      } catch (err) {
        console.error('Error loading benchmark data:', err);
        setError(err.message);
        setLoading(false);
      }
    };

    loadData();
  }, []);

  if (loading) {
    return (
      <div className="benchmarks-page">
        <div className="benchmarks-content">
          <div className="loading-state">
            <div className="spinner" />
            <p>Loading benchmark data...</p>
          </div>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="benchmarks-page">
        <div className="benchmarks-content">
          <div className="error-state">
            <p>Error loading data: {error}</p>
          </div>
        </div>
      </div>
    );
  }

  return (
    <>
      <Helmet>
        <title>Benchmarks & Methodology | ExtensionShield</title>
        <meta name="description" content="Coverage, performance, and governance/privacy signals — transparently documented. ExtensionShield scores beyond security into privacy and compliance signals." />
        <link rel="canonical" href="https://extensionaudit.com/research/benchmarks" />
      </Helmet>

      <div className="benchmarks-page">
        <div className="benchmarks-bg">
          <div className="bg-gradient" />
          <div className="bg-grid" />
        </div>

        <div className="benchmarks-content">
          {/* Hero Section */}
          <header className="benchmarks-header">
            <span className="benchmarks-badge">Benchmarks</span>
            <h1>Benchmarks & Methodology</h1>
            <p>
              Coverage, performance, and governance/privacy signals — transparently documented. ExtensionShield scores beyond security into privacy and compliance signals.
            </p>
          </header>

          {/* Industry Trends Section */}
          <section className="trends-section">
            <div className="section-header">
              <h2>Industry Trends</h2>
              <p>Rising threats in browser extensions</p>
            </div>

            <div className="charts-grid">
              <div className="chart-card">
                <TrendChart 
                  data={trendsData.maliciousExtensions}
                  dataKey="Malicious Extensions"
                  title="Reported extension enforcement & security advisories (selected sources)"
                  color="#ef4444"
                />
              </div>

              <div className="chart-card">
                <TrendChart 
                  data={trendsData.dataTheftIncidents}
                  dataKey="Data Theft Incidents"
                  title="Reported extension-related data exposure incidents (public reports)"
                  color="#f59e0b"
                />
              </div>
            </div>

            <div className="trends-disclaimer">
              <p>Compiled from public reporting; not a complete measure of all incidents.</p>
            </div>
          </section>

          {/* Benchmark Highlights */}
          <section className="highlights-section">
            <div className="highlights-grid">
              <div className="highlight-tile">
                <div className="highlight-number">9</div>
                <div className="highlight-label">Signal Categories</div>
                <div className="highlight-detail">Comprehensive coverage across security, privacy, and compliance</div>
              </div>
              
              <div className="highlight-tile">
                <div className="highlight-badge">✓ Included</div>
                <div className="highlight-label">Privacy + Compliance</div>
                <div className="highlight-detail">Beyond traditional security scanning</div>
              </div>
              
              <div className="highlight-tile">
                <div className="highlight-number">50+</div>
                <div className="highlight-label">Evidence Artifacts</div>
                <div className="highlight-detail">Hashes, rule hits, IOCs, screenshots</div>
              </div>
              
              <div className="highlight-tile">
                <div className="highlight-number">502</div>
                <div className="highlight-label">
                  {(() => {
                    const latestIncident = trendsData.maliciousExtensions[trendsData.maliciousExtensions.length - 1];
                    const hasSource = latestIncident && latestIncident.source_url;
                    return hasSource ? (
                      <>
                        Reported Incidents (Q4 2024)
                        <a 
                          href={latestIncident.source_url}
                          target="_blank"
                          rel="noreferrer noopener"
                          style={{
                            fontSize: '0.75rem',
                            color: '#22c55e',
                            textDecoration: 'none',
                            marginLeft: '0.5rem',
                            fontWeight: 500
                          }}
                          onClick={(e) => e.stopPropagation()}
                        >
                          Source →
                        </a>
                      </>
                    ) : 'Reported incidents (public reports)';
                  })()}
                </div>
                <div className="highlight-detail">From public reports</div>
              </div>
            </div>
          </section>

          {/* Data Sources Section */}
          <section className="sources-section">
            <div className="section-header">
              <h2>Data Sources</h2>
              <p>Credible sources for industry trend data</p>
            </div>
            <SourcesBox sources={trendsData.sources} />
          </section>

          {/* Capability Grid */}
          <section className="capability-section">
            <div className="section-header">
              <h2>Signals We Measure</h2>
              <p>Our rubric covers security, privacy, and compliance signals</p>
            </div>
            <div className="capability-grid">
              {[
                {
                  id: 'permissions',
                  name: 'Permissions',
                  status: 'implemented',
                  signals: [
                    'Host permissions mismatch',
                    'Overly broad requests',
                    'Permission-purpose alignment'
                  ],
                  allSignals: [
                    'Host permissions mismatch',
                    'Overly broad permission requests',
                    'Permission-purpose alignment',
                    'Optional vs required permissions',
                    'Permission escalation risks'
                  ]
                },
                {
                  id: 'network',
                  name: 'Network',
                  status: 'implemented',
                  signals: [
                    'Remote code fetch',
                    'Tracker endpoints',
                    'Data exfiltration'
                  ],
                  allSignals: [
                    'Remote code fetch',
                    'Tracker endpoints',
                    'Third-party domain analysis',
                    'HTTPS enforcement',
                    'Data exfiltration patterns',
                    'CORS policy violations'
                  ]
                },
                {
                  id: 'sast',
                  name: 'SAST',
                  status: 'implemented',
                  signals: [
                    'Static code analysis',
                    'Malicious patterns',
                    'Code injection risks'
                  ],
                  allSignals: [
                    'Static code analysis',
                    'Obfuscation detection',
                    'Malicious pattern matching',
                    'Code injection risks',
                    'Eval() usage detection',
                    'Dynamic import analysis'
                  ]
                },
                {
                  id: 'obfuscation',
                  name: 'Obfuscation',
                  status: 'implemented',
                  signals: [
                    'Code obfuscation',
                    'String encoding',
                    'Base64 detection'
                  ],
                  allSignals: [
                    'Code obfuscation detection',
                    'String encoding analysis',
                    'Minification patterns',
                    'Base64 encoding detection',
                    'Unicode obfuscation'
                  ]
                },
                {
                  id: 'reputation',
                  name: 'Reputation',
                  status: 'implemented',
                  signals: [
                    'User review analysis',
                    'Store ratings',
                    'Developer reputation'
                  ],
                  allSignals: [
                    'User review analysis',
                    'Store rating trends',
                    'Developer reputation',
                    'Report history',
                    'Community feedback'
                  ]
                },
                {
                  id: 'privacy',
                  name: 'Privacy',
                  status: 'implemented',
                  signals: [
                    'Data collection patterns',
                    'Tracking surface',
                    'PII exposure risks'
                  ],
                  allSignals: [
                    'Data collection patterns',
                    'Tracking surface analysis',
                    'PII exposure risks',
                    'User data handling',
                    'Cookie & storage analysis',
                    'Cross-site tracking detection'
                  ]
                },
                {
                  id: 'governance',
                  name: 'Governance',
                  status: 'implemented',
                  signals: [
                    'Policy/auditability',
                    'Transparency indicators',
                    'Evidence chain'
                  ],
                  allSignals: [
                    'Policy/auditability signals',
                    'Transparency indicators',
                    'Compliance tracking',
                    'Evidence chain-of-custody',
                    'Audit trail generation'
                  ]
                },
                {
                  id: 'tos-policy',
                  name: 'ToS/Policy',
                  status: 'implemented',
                  signals: [
                    'Store policy violations',
                    'Deception indicators',
                    'Intent mismatch'
                  ],
                  allSignals: [
                    'Store policy violations',
                    'Deception risk indicators',
                    'Automation tool detection',
                    'Intent mismatch analysis',
                    'Affiliate link hijacking'
                  ]
                },
                {
                  id: 'evidence',
                  name: 'Evidence',
                  status: 'implemented',
                  signals: [
                    'Reproducible artifacts',
                    'File hashes',
                    'IOC tracking'
                  ],
                  allSignals: [
                    'Reproducible artifacts',
                    'File hashes & signatures',
                    'Rule hit documentation',
                    'IOC tracking',
                    'Screenshot evidence',
                    'Network capture logs'
                  ]
                }
              ].map((category) => (
                <div 
                  key={category.id}
                  className={`capability-card ${expandedCategory === category.id ? 'expanded' : ''}`}
                  onClick={() => setExpandedCategory(expandedCategory === category.id ? null : category.id)}
                >
                  <div className="capability-header">
                    <h4>{category.name}</h4>
                    <span className="status-badge implemented">Implemented</span>
                  </div>
                  <ul className="capability-signals">
                    {category.signals.map((signal, index) => (
                      <li key={index}>{signal}</li>
                    ))}
                  </ul>
                  {expandedCategory === category.id && (
                    <div className="capability-expanded">
                      <ul className="capability-signals-full">
                        {category.allSignals.map((signal, index) => (
                          <li key={index}>{signal}</li>
                        ))}
                      </ul>
                    </div>
                  )}
                </div>
              ))}
            </div>
          </section>

          {/* Safer Alternatives */}
          <section className="recommendations-section">
            <div className="section-header">
              <h2>Safer Alternative Recommendations</h2>
              <p>When risk is elevated, we suggest lower-risk alternatives in the same category (based on our rubric + public signals).</p>
            </div>
            
            <div className="recommendations-grid">
              {benchmarksData.differentiators.safer_alternatives.example_recommendations.map((rec, index) => (
                <div key={index} className="recommendation-card">
                  <div className="recommendation-header">
                    <h4>{rec.name}</h4>
                    <span className="risk-badge">Recommended alternative</span>
                  </div>
                  <p className="recommendation-reason">{rec.reason}</p>
                  <div className="recommendation-actions">
                    <a 
                      href={rec.reportUrl || `/extension/${rec.name.toLowerCase().replace(/\s+/g, '-')}`} 
                      className="recommendation-link primary"
                    >
                      View report →
                    </a>
                    {rec.storeUrl && (
                      <>
                        <span style={{ color: '#64748b', margin: '0 0.5rem' }}>·</span>
                        <a 
                          href={rec.storeUrl} 
                          target="_blank"
                          rel="noreferrer noopener"
                          className="recommendation-link secondary"
                        >
                          Chrome Web Store
                        </a>
                      </>
                    )}
                  </div>
                </div>
              ))}
            </div>
          </section>
        </div>
      </div>
    </>
  );
};

export default BenchmarksPage;

