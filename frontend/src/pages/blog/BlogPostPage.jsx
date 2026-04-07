import React from "react";
import { Link, useLocation, useNavigate } from "react-router-dom";
import SEOHead from "../../components/SEOHead";
import { getBlogPostBySlug } from "../../data/blogPosts";
import "../compare/ComparePage.scss";
import "./BlogPostPage.scss";

const BlogPostPage = () => {
  const location = useLocation();
  const navigate = useNavigate();
  const slug = location.pathname.replace(/^\/blog\/?/, "").replace(/\/$/, "");
  const post = getBlogPostBySlug(slug);

  if (!post) {
    return (
      <div className="blog-post-page">
        <div className="compare-container">
          <p>Post not found.</p>
          <Link to="/blog">Back to blog</Link>
        </div>
      </div>
    );
  }

  return (
    <>
      <SEOHead
        title={post.title}
        description={post.description}
        pathname={`/blog/${post.slug}`}
        ogType="article"
      />

      <div className="blog-post-page">
        <div className="compare-container">
          <div className="compare-back-wrapper">
          <button type="button" className="compare-back" onClick={() => navigate(-1)}>
            ← Back
          </button>
          </div>

          <header className="compare-header">
            <span className="blog-post-meta">
              {post.category} · {post.date}
            </span>
            <h1>{post.title}</h1>
          </header>

          <div className="compare-prose">
            {post.sections.map((section, idx) => (
              <section key={idx}>
                <h2>{section.heading}</h2>
                <p>{section.body}</p>
              </section>
            ))}
          </div>

          <div className="compare-cta">
            <Link to="/scan">Scan an extension with ExtensionShield →</Link>
          </div>

          <div className="compare-links">
            <Link to="/blog">← All blog posts</Link>
          </div>
        </div>
      </div>
    </>
  );
};

export default BlogPostPage;
