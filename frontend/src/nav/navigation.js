/**
 * Navigation: top nav, mega menu, footer.
 * Logo links to "/", so a separate Home item is omitted.
 * Categories: Product, Research, Enterprise, Resources.
 */
export const NAV_CATEGORIES = {
  PRODUCT: "Product",
  RESEARCH: "Research",
  ENTERPRISE: "Enterprise",
  RESOURCES: "Resources",
};

export const topNavItems = [
  {
    category: NAV_CATEGORIES.PRODUCT,
    label: "Scan",
    path: "/scan",
    matchPaths: ["/scan"],
    dropdownItems: [
      {
        icon: "🔍",
        label: "Scan a Public Extension (URL or ID)",
        description: "Chrome Web Store URL or ID",
        path: "/scan"
      },
      {
        icon: "📦",
        label: "Upload CRX/ZIP",
        description: "Private pre-release audit",
        path: "/scan/upload",
        badge: "PRO"
      },
      {
        icon: "🕐",
        label: "Scan History",
        description: "Your past scans",
        path: "/scan/history"
      }
    ]
  },
  {
    category: NAV_CATEGORIES.RESEARCH,
    label: "Research",
    path: "/research",
    matchPaths: ["/research", "/compare"],
    dropdownItems: [
      {
        icon: "📋",
        label: "Case Studies",
        description: "Real-world analysis",
        path: "/research/case-studies"
      },
      {
        icon: "⚙️",
        label: "How We Score",
        description: "How we score risk",
        path: "/research/methodology"
      },
      {
        icon: "benchmarks",
        label: "Benchmarks",
        description: "Industry trends & scoring",
        path: "/research/benchmarks"
      },
      {
        icon: "compare",
        label: "Compare Scanners",
        description: "ExtensionShield vs alternatives",
        path: "/compare"
      }
    ]
  },
  {
    category: NAV_CATEGORIES.ENTERPRISE,
    label: "Enterprise",
    path: "/enterprise",
    matchPaths: ["/enterprise"],
    dropdownItems: [
      {
        icon: "🏢",
        label: "Governance",
        description: "Org reports & policies",
        path: "/enterprise"
      },
      {
        icon: "📡",
        label: "Monitoring & Alerts",
        description: "Real-time updates",
        path: "/enterprise#monitoring"
      }
    ]
  }
];

/**
 * Mega Menu Configuration
 * Resources dropdown - Open Source, Community, About, Blog, Contribute
 */
export const megaMenuConfig = {
  category: NAV_CATEGORIES.RESOURCES,
  trigger: {
    label: "Resources",
    matchPaths: ["/open-source", "/community", "/about", "/blog", "/contribute"]
  },
  items: [
    {
      icon: "🌱",
      label: "Open Source",
      description: "Contribute & explore",
      path: "/open-source"
    },
    {
      icon: "💬",
      label: "Community",
      description: "Safety notes & alternatives",
      path: "/community"
    },
    {
      icon: "📝",
      label: "Blog",
      description: "Security guides & updates",
      path: "/blog"
    },
    {
      icon: "🤝",
      label: "Contribute",
      description: "How to contribute",
      path: "/contribute"
    },
    {
      icon: "👤",
      label: "About",
      description: "Founder's story",
      path: "/about"
    }
  ]
};

/**
 * Build sections for mobile menu: each section has a category label and links.
 */
export function getMobileNavSections() {
  const sections = [];
  topNavItems.forEach((item) => {
    const links = item.dropdownItems
      ? item.dropdownItems.map((d) => ({
          label: d.label,
          path: d.path,
          external: d.external,
          href: d.href,
        }))
      : [{ label: item.label, path: item.path }];
    sections.push({ category: item.category, links });
  });
  sections.push({
    category: megaMenuConfig.category,
    links: megaMenuConfig.items.map((i) => ({
      label: i.label,
      path: i.path,
      external: i.external,
      href: i.href,
    })),
  });
  return sections;
}

/**
 * User Menu Items (authenticated users)
 */
export const userMenuItems = [
  {
    icon: "scan",
    label: "Scan",
    path: "/scan"
  },
  {
    icon: "history",
    label: "Scan History",
    path: "/scan/history"
  },
  {
    icon: "settings",
    label: "Settings",
    path: "/settings"
  }
];

/**
 * Footer Configuration
 * Two-column layout: left = brand + disclaimer, right = link groups.
 */
export const footerConfig = {
  disclaimer: "Comprehensive extension governance through security, privacy, and compliance analysis. We aggregate multiple dimensions into a single actionable score. So you can trust the results you find.",
  tagline: "Extension security you can trust.",
  linkGroups: [
    {
      heading: "Product",
      links: [
        { label: "Scan", path: "/scan" },
        { label: "Upload CRX/ZIP", path: "/scan/upload" },
        { label: "Is extension safe?", path: "/is-this-chrome-extension-safe" },
        { label: "Scan History", path: "/scan/history" }
      ]
    },
    {
      heading: "Research",
      links: [
        { label: "How We Score", path: "/research/methodology" },
        { label: "Case Studies", path: "/research/case-studies" },
        { label: "Compare Scanners", path: "/compare" },
        { label: "Benchmarks", path: "/research/benchmarks" }
      ]
    },
    {
      heading: "Company",
      links: [
        { label: "Enterprise", path: "/enterprise" },
        { label: "Blog", path: "/blog" },
        { label: "Contribute", path: "/contribute" }
      ]
    },
    {
      heading: "Legal & Community",
      links: [
        { label: "Privacy Policy", path: "/privacy-policy" },
        { label: "GitHub", href: "https://github.com/Stanzin7/ExtensionScanner", external: true }
      ]
    }
  ]
};

export default {
  topNavItems,
  megaMenuConfig,
  userMenuItems,
  footerConfig,
  getMobileNavSections,
  NAV_CATEGORIES,
};

