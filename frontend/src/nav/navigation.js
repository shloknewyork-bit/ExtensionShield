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
    matchPaths: ["/scan"]
  },
  {
    label: "Research",
    path: "/research",
    matchPaths: ["/research"]
  },
  {
    label: "Enterprise",
    path: "/enterprise",
    matchPaths: ["/enterprise"]
  }
];

/**
 * Mega Menu Configuration
 * 4-column layout with sections
 */
export const megaMenuConfig = {
  trigger: {
    label: "Resources",
    matchPaths: ["/scan", "/research", "/open-source", "/gsoc", "/contribute"]
  },
  sections: [
    {
      id: "scan",
      title: "Scan",
      items: [
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
      id: "enterprise",
      title: "Enterprise",
      items: [
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
    },
    {
      id: "research",
      title: "Research",
      items: [
        {
          icon: "📋",
          label: "Case Studies",
          description: "Real-world analysis",
          path: "/research/case-studies"
        },
        {
          icon: "⚙️",
          label: "Methodology",
          description: "How we score risk",
          path: "/research/methodology"
        }
      ]
    },
    {
      id: "open-source",
      title: "Open Source",
      items: [
        {
          icon: "🌱",
          label: "Open Source",
          description: "Contribute & explore",
          path: "/open-source"
        },
        {
          icon: "☀️",
          label: "GSoC Ideas",
          description: "Summer of Code projects",
          path: "/gsoc/ideas"
        },
        {
          icon: "🤝",
          label: "Contribute",
          description: "Get started guide",
          path: "/contribute"
        },
        {
          icon: "github",
          label: "GitHub",
          description: "View source code",
          href: "https://github.com/Stanzin7/ExtensionShield",
          external: true
        }
      ]
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
 * Footer Links
 */
export const footerLinks = [
  {
    label: "Methodology",
    path: "/research/methodology"
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
];

export default {
  topNavItems,
  megaMenuConfig,
  userMenuItems,
  footerLinks
};

