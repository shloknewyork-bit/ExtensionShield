#!/usr/bin/env node

/**
 * Sitemap Generator
 * 
 * Generates sitemap.xml from route configuration
 * Run: npm run generate:sitemap
 * 
 * Uses VITE_SITE_URL environment variable or defaults to https://extensionaudit.com
 */

import { writeFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));

// Site URL from environment or default
const SITE_URL = process.env.VITE_SITE_URL || 'https://extensionaudit.com';

// Route definitions with SEO metadata
// NOTE: Keep in sync with src/routes/routes.jsx
const sitemapRoutes = [
  {
    path: '/',
    priority: 1.0,
    changefreq: 'weekly'
  },
  {
    path: '/scan',
    priority: 0.9,
    changefreq: 'weekly'
  },
  {
    path: '/scan/history',
    priority: 0.7,
    changefreq: 'weekly'
  },
  {
    path: '/research',
    priority: 0.8,
    changefreq: 'weekly'
  },
  {
    path: '/research/case-studies',
    priority: 0.8,
    changefreq: 'weekly'
  },
  {
    path: '/research/case-studies/honey',
    priority: 0.7,
    changefreq: 'monthly'
  },
  {
    path: '/research/methodology',
    priority: 0.7,
    changefreq: 'monthly'
  },
  {
    path: '/enterprise',
    priority: 0.8,
    changefreq: 'monthly'
  },
  {
    path: '/open-source',
    priority: 0.7,
    changefreq: 'monthly'
  },
  {
    path: '/gsoc/ideas',
    priority: 0.7,
    changefreq: 'monthly'
  },
  {
    path: '/contribute',
    priority: 0.6,
    changefreq: 'monthly'
  },
  {
    path: '/gsoc/community',
    priority: 0.5,
    changefreq: 'monthly'
  },
  {
    path: '/gsoc/blog',
    priority: 0.5,
    changefreq: 'weekly'
  }
];

function generateSitemap() {
  const urls = sitemapRoutes.map(route => {
    const loc = `${SITE_URL}${route.path}`;
    const changefreq = route.changefreq || 'monthly';
    const priority = route.priority || 0.5;
    
    return `  <url>
    <loc>${loc}</loc>
    <changefreq>${changefreq}</changefreq>
    <priority>${priority.toFixed(1)}</priority>
  </url>`;
  }).join('\n');

  const sitemap = `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
${urls}
</urlset>`;

  return sitemap;
}

function main() {
  try {
    const sitemap = generateSitemap();
    const outputPath = join(__dirname, '../public/sitemap.xml');
    
    writeFileSync(outputPath, sitemap, 'utf-8');
    
    console.log('✅ Sitemap generated successfully!');
    console.log(`📍 Location: ${outputPath}`);
    console.log(`🌐 Site URL: ${SITE_URL}`);
    console.log(`📊 Routes: ${sitemapRoutes.length}`);
    
    // Warning about keeping in sync
    console.log('\n⚠️  Remember to keep scripts/generate-sitemap.js in sync with src/routes/routes.jsx');
  } catch (error) {
    console.error('❌ Error generating sitemap:', error.message);
    process.exit(1);
  }
}

main();

