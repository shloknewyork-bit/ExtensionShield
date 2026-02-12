/**
 * Navigation Configuration
 * 
 * This file contains all navigation structure for the app:
 * - Top navigation items
 * - Mega menu structure
 * - Footer links
 */

/**
 * Top Navigation Items
 * Note: Logo routes to "/" so "Home" is redundant
 */
export const topNavItems = [
  {
    label: "Scan",
    path: "/scan",
    matchPaths: ["/scan"],
    dropdownItems: [
      {
        icon: "🔍",
        label: "Start Scan",
        description: "Analyze any extension",
        path: "/scan"
      },
      {
        icon: "🕐",
        label: "Scan History",
        description: "Browse past scans",
        path: "/scan/history"
      }
    ]
  },
  {
    label: "Research",
    path: "/research",
    matchPaths: ["/research"],
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
      }
    ]
  },
  {
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
 * Resources dropdown - Open Source, Community, About
 */
export const megaMenuConfig = {
  trigger: {
    label: "Resources",
    matchPaths: ["/open-source", "/community", "/about"]
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
      icon: "👤",
      label: "About",
      description: "Founder's story",
      path: "/about"
    }
  ]
};

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
    icon: "reports",
    label: "Reports",
    path: "/reports"
  },
  {
    icon: "settings",
    label: "Settings",
    path: "/settings"
  }
];

/**
 * Footer Configuration
 */
export const footerConfig = {
  disclaimer: "Comprehensive extension governance through security, privacy, and compliance analysis. We aggregate multiple dimensions into a single actionable score. So you can trust the results you find.",
  links: [
    {
      label: "How We Score",
      path: "/research/methodology"
    },
    {
      label: "Privacy Policy",
      path: "/privacy-policy"
    },
    {
      label: "Contribute",
      path: "/contribute"
    },
    {
      label: "GitHub",
      href: "https://github.com/Stanzin7/ExtensionShield",
      external: true
    }
  ]
};

export default {
  topNavItems,
  megaMenuConfig,
  userMenuItems,
  footerConfig
};

