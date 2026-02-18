# Header, Navigation & Megamenu — Paste Package for Other Sites

Same design as ExtensionShield (glass pill on scroll, emerald accents, megamenu, Sign In button style). Copy these files into your project.

---

## 1. Navigation Config — `nav/navigation.js`

```javascript
/**
 * Navigation: top nav items, mega menu config.
 */
export const topNavItems = [
  {
    label: "Scan",
    path: "/scan",
    matchPaths: ["/scan"],
    dropdownItems: [
      { icon: "🔍", label: "Start Scan", description: "Analyze any extension", path: "/scan" },
      { icon: "🕐", label: "Scan History", description: "Browse past scans", path: "/scan/history" }
    ]
  },
  {
    label: "Research",
    path: "/research",
    matchPaths: ["/research"],
    dropdownItems: [
      { icon: "📋", label: "Case Studies", description: "Real-world analysis", path: "/research/case-studies" },
      { icon: "⚙️", label: "How We Score", description: "How we score risk", path: "/research/methodology" },
      { icon: "benchmarks", label: "Benchmarks", description: "Industry trends", path: "/research/benchmarks" }
    ]
  },
  {
    label: "Enterprise",
    path: "/enterprise",
    matchPaths: ["/enterprise"],
    dropdownItems: [
      { icon: "🏢", label: "Governance", description: "Org reports & policies", path: "/enterprise" },
      { icon: "📡", label: "Monitoring & Alerts", description: "Real-time updates", path: "/enterprise#monitoring" }
    ]
  }
];

export const megaMenuConfig = {
  trigger: { label: "Resources", matchPaths: ["/resources", "/open-source", "/community", "/about"] },
  items: [
    { icon: "📡", label: "API Service", description: "API access & payload reference", path: "/resources/api-service" },
    { icon: "🌱", label: "Open Source", description: "Contribute & explore", path: "/open-source" },
    { icon: "💬", label: "Community", description: "Safety notes & alternatives", path: "/community" },
    { icon: "👤", label: "About", description: "Founder's story", path: "/about" }
  ]
};
```

---

## 2. Theme Variables (add to your global CSS)

```css
/* Atlas theme tokens — used by header/megamenu (Sign In design) */
:root {
  --atlas-header-height: 72px;
  --atlas-header-offset: calc(var(--atlas-header-height) + 1rem);
  --atlas-text-primary: #f5f3f0;
  --atlas-text-secondary: #b8b3ab;
  --atlas-text-muted: #9a958d;
  --atlas-accent: #22c55e;
  --atlas-accent-hover: #16a34a;
  --atlas-accent-subtle: rgba(34, 197, 94, 0.14);
  --atlas-border: rgba(180, 172, 157, 0.22);
  --atlas-border-accent: rgba(34, 197, 94, 0.35);
  --font-sans: 'DM Sans', -apple-system, BlinkMacSystemFont, sans-serif;
}

.light {
  --atlas-accent: #15803d;
  --atlas-accent-hover: #166534;
  --atlas-accent-subtle: rgba(21, 128, 61, 0.12);
}
```

---

## 3. Header Component — `components/Header.jsx`

```jsx
import React from "react";
import { createPortal } from "react-dom";
import { motion } from "framer-motion";
import { NavLink, useLocation } from "react-router-dom";
import { topNavItems, megaMenuConfig } from "../nav/navigation";

// ============ NAV ITEM DROPDOWN ============
function NavItemDropdown({ item, location }) {
  const [isOpen, setIsOpen] = React.useState(false);
  const menuRef = React.useRef(null);
  const timeoutRef = React.useRef(null);
  const isActive = item.matchPaths?.some((path) => location.pathname.startsWith(path)) ?? false;

  React.useEffect(() => {
    const handler = (e) => {
      if (menuRef.current && !menuRef.current.contains(e.target)) setIsOpen(false);
    };
    if (isOpen) document.addEventListener("mousedown", handler);
    return () => document.removeEventListener("mousedown", handler);
  }, [isOpen]);

  React.useEffect(() => () => { if (timeoutRef.current) clearTimeout(timeoutRef.current); }, []);

  const handleMouseEnter = () => {
    if (timeoutRef.current) clearTimeout(timeoutRef.current);
    timeoutRef.current = null;
    setIsOpen(true);
  };
  const handleMouseLeave = () => { timeoutRef.current = setTimeout(() => setIsOpen(false), 150); };

  const renderIcon = (icon) => {
    if (icon === "github")
      return <svg viewBox="0 0 24 24" fill="currentColor" width="20" height="20"><path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z" /></svg>;
    if (icon === "benchmarks")
      return <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M3 17l6-6 4 4 8-10" /><path d="M21 7v6h-6" /></svg>;
    return icon;
  };

  if (!item.dropdownItems?.length) {
    return (
      <NavLink to={item.path} className={({ isActive: a }) => `nav-item ${a || isActive ? "active" : ""}`}>
        {item.label}
      </NavLink>
    );
  }

  return (
    <div className="nav-dropdown-container" ref={menuRef} onMouseEnter={handleMouseEnter} onMouseLeave={handleMouseLeave}>
      <button className={`nav-item nav-dropdown-trigger ${isActive ? "active" : ""} ${isOpen ? "open" : ""}`} onClick={() => setIsOpen(!isOpen)}>
        {item.label}
        <svg width="12" height="12" viewBox="0 0 12 12" fill="none" stroke="currentColor" strokeWidth="2">
          <path d={isOpen ? "M3 9l3-3 3 3" : "M3 3l3 3 3-3"} />
        </svg>
      </button>
      {isOpen && (
        <div className="nav-dropdown-menu" onMouseEnter={handleMouseEnter} onMouseLeave={handleMouseLeave}>
          {item.dropdownItems.map((d, idx) => {
            const El = d.external ? "a" : NavLink;
            const props = d.external ? { href: d.href, target: "_blank", rel: "noopener noreferrer" } : { to: d.path };
            return (
              <El key={idx} {...props} className="nav-dropdown-item" onClick={() => setIsOpen(false)}>
                <div className="nav-dropdown-icon">{renderIcon(d.icon)}</div>
                <div className="nav-dropdown-content">
                  <div className="nav-dropdown-label">{d.label}</div>
                  <div className="nav-dropdown-desc">{d.description}</div>
                </div>
              </El>
            );
          })}
        </div>
      )}
    </div>
  );
}

// ============ MEGAMENU ============
function MainMegamenu() {
  const location = useLocation();
  const [isOpen, setIsOpen] = React.useState(false);
  const menuRef = React.useRef(null);
  const timeoutRef = React.useRef(null);
  const isActive = megaMenuConfig.trigger.matchPaths.some((path) => location.pathname.startsWith(path));

  React.useEffect(() => {
    const handler = (e) => { if (menuRef.current && !menuRef.current.contains(e.target)) setIsOpen(false); };
    if (isOpen) document.addEventListener("mousedown", handler);
    return () => document.removeEventListener("mousedown", handler);
  }, [isOpen]);

  React.useEffect(() => () => { if (timeoutRef.current) clearTimeout(timeoutRef.current); }, []);

  const handleMouseEnter = () => { if (timeoutRef.current) clearTimeout(timeoutRef.current); timeoutRef.current = null; setIsOpen(true); };
  const handleMouseLeave = () => { timeoutRef.current = setTimeout(() => setIsOpen(false), 150); };

  const renderIcon = (icon) => {
    if (icon === "github")
      return <svg viewBox="0 0 24 24" fill="currentColor" width="20" height="20"><path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z" /></svg>;
    return icon;
  };

  return (
    <div className="megamenu-container" ref={menuRef} onMouseEnter={handleMouseEnter} onMouseLeave={handleMouseLeave}>
      <button className={`nav-item megamenu-trigger ${isActive ? "active" : ""} ${isOpen ? "open" : ""}`} onClick={() => setIsOpen(!isOpen)}>
        {megaMenuConfig.trigger.label}
        <svg width="12" height="12" viewBox="0 0 12 12" fill="none" stroke="currentColor" strokeWidth="2">
          <path d={isOpen ? "M3 9l3-3 3 3" : "M3 3l3 3 3-3"} />
        </svg>
      </button>
      {isOpen && (
        <div className="megamenu-dropdown" onMouseEnter={handleMouseEnter} onMouseLeave={handleMouseLeave}>
          <div className="megamenu-items-list">
            {megaMenuConfig.items.map((it, idx) => {
              const El = it.external ? "a" : NavLink;
              const props = it.external ? { href: it.href, target: "_blank", rel: "noopener noreferrer" } : { to: it.path };
              return (
                <El key={idx} {...props} className="megamenu-item" onClick={() => setIsOpen(false)}>
                  <div className="megamenu-icon">{renderIcon(it.icon)}</div>
                  <div className="megamenu-content">
                    <div className="megamenu-label">{it.label}</div>
                    <div className="megamenu-desc">{it.description}</div>
                  </div>
                </El>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
}

// ============ APP HEADER ============
const HEADER_SCROLL_THRESHOLD = 100;

export default function Header({ theme = "dark", onSignIn, ThemeToggle, LogoComponent, siteName = "YourSite" }) {
  const location = useLocation();
  const isLight = theme === "light";
  const [scrolled, setScrolled] = React.useState(false);
  const [mobileMenuOpen, setMobileMenuOpen] = React.useState(false);
  const mobileMenuRef = React.useRef(null);

  React.useEffect(() => {
    const handleScroll = () => setScrolled(window.scrollY > HEADER_SCROLL_THRESHOLD);
    handleScroll();
    window.addEventListener("scroll", handleScroll, { passive: true });
    return () => window.removeEventListener("scroll", handleScroll);
  }, []);

  React.useEffect(() => setMobileMenuOpen(false), [location.pathname]);

  React.useEffect(() => {
    const handler = (e) => {
      if (mobileMenuRef.current && !mobileMenuRef.current.contains(e.target) && !e.target.closest(".header-mobile-toggle"))
        setMobileMenuOpen(false);
    };
    if (mobileMenuOpen) { document.addEventListener("mousedown", handler); document.body.style.overflow = "hidden"; }
    return () => { document.removeEventListener("mousedown", handler); document.body.style.overflow = ""; };
  }, [mobileMenuOpen]);

  const headerSolid = scrolled;
  const headerClass = headerSolid ? "solid" : "transparent";

  const containerVariants = {
    transparent: {
      borderRadius: 0, maxWidth: "1600px", margin: "0 auto",
      background: "transparent", backdropFilter: "none", WebkitBackdropFilter: "none",
      boxShadow: "none", border: "1px solid transparent",
    },
    solid: {
      borderRadius: 9999, maxWidth: "1600px", margin: "0 auto",
      background: isLight ? "rgba(250, 248, 244, 0.78)" : "transparent",
      backdropFilter: "blur(24px)", WebkitBackdropFilter: "blur(24px)",
      boxShadow: isLight
        ? "0 4px 24px rgba(38, 35, 31, 0.1), 0 0 0 1px rgba(38, 35, 31, 0.08)"
        : "0 0 24px rgba(34, 197, 94, 0.08), 0 4px 24px rgba(0, 0, 0, 0.25)",
      border: isLight ? "1px solid rgba(38, 35, 31, 0.14)" : "1px solid rgba(34, 197, 94, 0.2)",
    },
  };

  const allNavLinks = [
    ...topNavItems.flatMap((item) =>
      item.dropdownItems
        ? item.dropdownItems.map((d) => ({ label: d.label, path: d.path, external: d.external, href: d.href }))
        : [{ label: item.label, path: item.path }]
    ),
    ...megaMenuConfig.items.map((it) => ({ label: it.label, path: it.path, external: it.external, href: it.href })),
  ];

  const Logo = LogoComponent;

  return (
    <header className={`atlas-header ${headerClass}`}>
      <motion.div
        className="header-container"
        animate={headerSolid ? "solid" : "transparent"}
        variants={containerVariants}
        transition={{ type: "spring", stiffness: 260, damping: 30, mass: 0.8 }}
      >
        <NavLink to="/" className="header-logo" onClick={() => setMobileMenuOpen(false)}>
          <div className="header-logo-shield" aria-hidden="true">
            {Logo ? (typeof Logo === "function" ? <Logo /> : Logo) : <span className="logo-text">{siteName.slice(0, 2).toUpperCase()}</span>}
          </div>
          <span className="logo-text">{siteName}</span>
        </NavLink>

        <nav className="header-nav header-nav-desktop" aria-label="Main">
          {topNavItems.map((item) => <NavItemDropdown key={item.path} item={item} location={location} />)}
          <MainMegamenu />
        </nav>

        <div className="header-actions header-actions-desktop">
          {ThemeToggle && <ThemeToggle />}
          {onSignIn && (
            <button type="button" className="action-signin" onClick={onSignIn}>Sign In</button>
          )}
        </div>

        <div className="header-actions header-actions-mobile">
          {ThemeToggle && <ThemeToggle />}
        </div>

        <button
          type="button"
          className="header-mobile-toggle"
          onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
          aria-label={mobileMenuOpen ? "Close menu" : "Open menu"}
          aria-expanded={mobileMenuOpen}
        >
          <span className="hamburger-bar" />
          <span className="hamburger-bar" />
          <span className="hamburger-bar" />
        </button>
      </motion.div>

      {createPortal(
        <div ref={mobileMenuRef} className={`mobile-menu ${mobileMenuOpen ? "mobile-menu-open" : ""}`} aria-hidden={!mobileMenuOpen}>
          <nav className="mobile-menu-nav" aria-label="Mobile">
            {allNavLinks.map((link, idx) => {
              const key = link.path || link.href || idx;
              if (link.external && link.href)
                return <a key={key} href={link.href} target="_blank" rel="noopener noreferrer" className="mobile-menu-link" onClick={() => setMobileMenuOpen(false)}>{link.label}</a>;
              return <NavLink key={key} to={link.path} className="mobile-menu-link" onClick={() => setMobileMenuOpen(false)}>{link.label}</NavLink>;
            })}
          </nav>
          <div className="mobile-menu-actions">
            {onSignIn && <button type="button" className="action-signin mobile-signin" onClick={() => { onSignIn(); setMobileMenuOpen(false); }}>Sign In</button>}
          </div>
        </div>,
        document.body
      )}
    </header>
  );
}
```

---

## 4. Header Styles — `components/Header.scss`

```scss
@import url('https://fonts.googleapis.com/css2?family=DM+Sans:ital,opsz,wght@0,9..40,100..1000&display=swap');

/* ============ HEADER ============ */
.atlas-header {
  position: fixed;
  top: 0;
  left: 0;
  right: 0;
  z-index: 1100;
  padding-top: 1rem;
  padding-left: 1rem;
  padding-right: 1rem;
  min-height: calc(var(--atlas-header-height) + 1rem);
  display: flex;
  align-items: flex-start;
  justify-content: center;
  background: transparent;
  pointer-events: none;
  > * { pointer-events: auto; }
}

.header-container {
  width: 100%;
  max-width: 1600px;
  height: var(--atlas-header-height);
  padding: 0 2rem;
  display: flex;
  align-items: center;
  justify-content: space-between;
}

.header-logo {
  display: flex;
  align-items: center;
  gap: 0.75rem;
  text-decoration: none;
  transition: all 0.2s ease;
  &:hover { opacity: 0.9; .header-logo-shield { transform: scale(1.05); } }
}

.header-logo-shield {
  width: 48px;
  height: 48px;
  display: flex;
  align-items: center;
  justify-content: center;
  flex-shrink: 0;
  transition: transform 0.2s ease;
}

.logo-text {
  font-size: 1.125rem;
  font-weight: 600;
  color: var(--atlas-text-primary);
  letter-spacing: -0.01em;
}

/* ============ NAV ============ */
.header-nav { display: flex; align-items: center; gap: 0.5rem; }

.nav-item {
  padding: 0.625rem 1.125rem;
  font-size: 0.9375rem;
  font-weight: 500;
  color: var(--atlas-text-secondary);
  text-decoration: none;
  border-radius: 8px;
  transition: all 0.2s ease;
  &:hover { color: var(--atlas-text-primary); background: rgba(255, 255, 255, 0.05); }
  &.active { color: var(--atlas-text-primary); background: rgba(34, 197, 94, 0.1); }
}

/* ============ MEGAMENU & DROPDOWNS ============ */
.megamenu-container, .nav-dropdown-container { position: relative; }

.megamenu-trigger, .nav-dropdown-trigger {
  display: flex;
  align-items: center;
  gap: 0.375rem;
  cursor: pointer;
  border: none;
  background: none;
  font-family: inherit;
  svg { transition: transform 0.2s ease; }
  &.open svg { transform: rotate(180deg); }
}

@keyframes megamenuEnter {
  from { opacity: 0; transform: translateY(-10px); }
  to { opacity: 1; transform: translateY(0); }
}

.megamenu-dropdown, .nav-dropdown-menu {
  position: absolute;
  top: calc(100% + 0.25rem);
  left: 0;
  min-width: 280px;
  background: rgba(15, 23, 42, 0.97);
  backdrop-filter: blur(20px);
  -webkit-backdrop-filter: blur(20px);
  border: 1px solid rgba(148, 163, 184, 0.12);
  border-radius: 12px;
  box-shadow: 0 4px 24px rgba(0, 0, 0, 0.4), 0 0 0 1px rgba(148, 163, 184, 0.06);
  padding: 0.75rem;
  z-index: 1300;
  animation: megamenuEnter 0.2s ease;
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
}

.megamenu-dropdown { width: 320px; }

.light .megamenu-dropdown, .light .nav-dropdown-menu {
  background: rgba(255, 255, 255, 0.94);
  border: 1px solid rgba(0, 0, 0, 0.06);
  box-shadow: 0 4px 24px rgba(0, 0, 0, 0.1), 0 0 1px rgba(0, 0, 0, 0.05);
}

.megamenu-item, .nav-dropdown-item {
  display: flex;
  align-items: flex-start;
  gap: 0.75rem;
  padding: 0.875rem;
  border-radius: 10px;
  text-decoration: none;
  color: var(--atlas-text-primary);
  transition: all 0.2s ease;
  border: 1px solid transparent;
  &:hover {
    background: rgba(148, 163, 184, 0.08);
    border-color: rgba(148, 163, 184, 0.15);
    transform: translateX(4px);
  }
}

.light .megamenu-item:hover, .light .nav-dropdown-item:hover {
  background: rgba(0, 0, 0, 0.04);
  border-color: rgba(0, 0, 0, 0.08);
}

.megamenu-icon, .nav-dropdown-icon {
  font-size: 1.25rem;
  flex-shrink: 0;
  width: 2rem;
  height: 2rem;
  display: flex;
  align-items: center;
  justify-content: center;
}
.megamenu-icon { background: rgba(148, 163, 184, 0.1); border-radius: 8px; }

.megamenu-content, .nav-dropdown-content { flex: 1; min-width: 0; }

.megamenu-label, .nav-dropdown-label {
  font-size: 0.875rem;
  font-weight: 600;
  color: var(--atlas-text-primary);
  margin-bottom: 0.125rem;
  line-height: 1.2;
}

.megamenu-desc, .nav-dropdown-desc {
  font-size: 0.75rem;
  color: rgba(148, 163, 184, 0.7);
  line-height: 1.3;
}

.light .megamenu-label, .light .nav-dropdown-label { color: hsl(var(--color-foreground, 34 12% 10%)); }
.light .megamenu-desc, .light .nav-dropdown-desc { color: rgba(0, 0, 0, 0.6); }

.megamenu-items-list { display: flex; flex-direction: column; gap: 0.5rem; }

/* ============ ACTIONS & SIGN IN (Sign In design) ============ */
.header-actions { display: flex; align-items: center; gap: 0.75rem; }
.header-actions-mobile { display: none; }

.action-signin {
  padding: 0.5rem 1.25rem;
  font-size: 0.9375rem;
  font-weight: 500;
  color: var(--atlas-text-primary);
  background: transparent;
  border: 1px solid rgba(148, 163, 184, 0.25);
  border-radius: 8px;
  cursor: pointer;
  transition: all 0.2s ease;
  font-family: inherit;
  &:hover {
    background: rgba(255, 255, 255, 0.06);
    border-color: rgba(148, 163, 184, 0.4);
    color: var(--atlas-text-primary);
  }
}

.light .action-signin {
  color: #fff;
  background: var(--atlas-accent);
  border-color: var(--atlas-accent);
  &:hover { background: var(--atlas-accent-hover); border-color: var(--atlas-accent-hover); color: #fff; }
}

/* ============ MOBILE MENU ============ */
.header-mobile-toggle {
  display: none;
  align-items: center;
  justify-content: center;
  width: 44px;
  height: 44px;
  padding: 0;
  border: 1px solid var(--atlas-border);
  background: color-mix(in srgb, var(--atlas-bg-secondary, #252320) 95%, var(--atlas-bg-primary, #1c1a17));
  border-radius: 10px;
  cursor: pointer;
  flex-direction: column;
  gap: 5px;
  .hamburger-bar {
    display: block;
    width: 20px;
    height: 2px;
    background: var(--atlas-text-primary);
    border-radius: 1px;
    transition: transform 0.25s ease, opacity 0.25s ease;
  }
}

.mobile-menu {
  position: fixed;
  top: var(--atlas-header-offset);
  left: 0;
  right: 0;
  bottom: 0;
  background: color-mix(in srgb, var(--atlas-bg-primary, #1c1a17) 98%, transparent);
  backdrop-filter: blur(20px);
  -webkit-backdrop-filter: blur(20px);
  border-top: 1px solid var(--atlas-border);
  padding: 1.5rem 1rem 2rem;
  overflow-y: auto;
  z-index: 1200;
  transform: translateX(100%);
  opacity: 0;
  visibility: hidden;
  transition: transform 0.25s cubic-bezier(0.22, 1, 0.36, 1), opacity 0.25s ease, visibility 0.25s ease;
  &.mobile-menu-open { transform: translateX(0); opacity: 1; visibility: visible; }
}

.mobile-menu-nav { display: flex; flex-direction: column; gap: 0.25rem; margin-bottom: 1.5rem; }
.mobile-menu-actions {
  padding-top: 1rem;
  border-top: 1px solid var(--atlas-border);
  display: flex;
  flex-direction: column;
  align-items: flex-end;
  .action-signin.mobile-signin { align-self: stretch; justify-content: center; }
}

.mobile-menu-link {
  display: block;
  padding: 0.875rem 1rem;
  font-size: 0.9375rem;
  font-weight: 500;
  color: var(--atlas-text-primary);
  text-decoration: none;
  border-radius: 10px;
  transition: background 0.2s ease, color 0.2s ease, box-shadow 0.2s ease;
  &:hover {
    background: var(--atlas-accent-subtle);
    box-shadow: inset 3px 0 0 var(--atlas-accent);
  }
}

/* Responsive */
@media (max-width: 900px) {
  :root { --atlas-header-height: 64px; }
  .header-nav-desktop, .header-actions-desktop { display: none !important; }
  .header-actions-mobile { display: flex; }
  .header-mobile-toggle { display: flex; }
}
@media (max-width: 480px) {
  :root { --atlas-header-height: 56px; }
}
```

---

## 5. Usage in Your App

```jsx
import Header from "./components/Header";
import "./components/Header.scss";

// If you have theme context:
function App() {
  const { theme } = useTheme();
  const openSignIn = () => { /* open your Sign In / Sign Up modal */ };

  return (
    <>
      <Header theme={theme} onSignIn={openSignIn} ThemeToggle={ThemeToggle} LogoComponent={YourLogo} />
      <main style={{ paddingTop: "var(--atlas-header-offset)" }}>...</main>
    </>
  );
}
```

**Dependencies:** `framer-motion`, `react-router-dom`  
**Theme:** Add the CSS variables from section 2 to your root styles. For light mode, add `.light` to `<html>` when using light theme.
