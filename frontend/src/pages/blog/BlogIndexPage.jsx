import React from "react";
import { Link, useNavigate } from "react-router-dom";
import SEOHead from "../../components/SEOHead";
import { blogPosts } from "../../data/blogPosts";
import "../compare/ComparePage.scss";
import "./BlogPostPage.scss";

const BlogIndexPage = () => {
  const navigate = useNavigate();

  return (
    <>
      <SEOHead
        title="Chrome Extension Security Blog | How to Audit & Check Extension Safety"
        description="How to check chrome extension permissions safely, detect malicious chrome extensions, and audit a chrome extension before installing. Extension security research and guides."
        pathname="/blog"
        ogType="website"
      />

      <div className="blog-post-page">
        <div className="compare-container">
          <div className="compare-back-wrapper">
          <button type="button" className="compare-back" onClick={() => navigate(-1)}>
            ← Back
          </button>
          </div>

          <header className="compare-header">
            <h1>Chrome Extension Security Blog</h1>
            <p>
              How to check chrome extension permissions safely, detect malicious chrome extensions, audit a chrome extension before installing, and manage enterprise browser extension risk. Guides and research from ExtensionShield.
            </p>
          </header>

          <ul className="blog-index-list">
            {blogPosts.map((post) => (
              <li key={post.slug}>
                <Link to={`/blog/${post.slug}`} className="blog-index-link">
                  <span className="blog-index-meta">{post.category} · {post.date}</span>
                  <strong>{post.title}</strong>
                  <span className="blog-index-desc">{post.description}</span>
                </Link>
              </li>
            ))}
          </ul>

          <div className="compare-cta">
            <Link to="/scan">Scan an extension with ExtensionShield →</Link>
          </div>
        </div>
      </div>
    </>
  );
};

export default BlogIndexPage;
