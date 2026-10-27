/**
 * ============================================================================
 * VULNERABLE ROUTE MODULE (EDUCATIONAL DEMONSTRATION ONLY)
 * ============================================================================
 * WARNING: This route is intentionally vulnerable to Reflected Cross-Site
 * Scripting (XSS). It is designed solely for local academic demonstration in a
 * college Web Server Security assignment.
 * 
 * Bound strictly to localhost (127.0.0.1). Do not expose to any public network.
 * ============================================================================
 */

const express = require('express');
const router = express.Router();
const { renderLayout } = require('../views/layout');
const { renderVulnerablePage } = require('../views/pages');

/**
 * Isolated Vulnerable Handler Function
 * 
 * TECHNICAL IMPLEMENTATION BREAKDOWN:
 * In this function:
 * 1. `req.query.q` captures untrusted user input directly from the URL query string.
 * 2. The input is passed directly to `renderVulnerablePage(rawQuery)` without any
 *    HTML entity encoding, filtering, or validation.
 * 3. `renderVulnerablePage` interpolates `rawQuery` directly into the HTML response body:
 *    `<p>Search results for: <strong>${rawQuery}</strong></p>`
 * 4. When the browser receives this response, its HTML parser encounters `<script>`
 *    or `<img onerror=...>` tags and transitions into JavaScript execution mode.
 */
function handleVulnerableSearch(req, res) {
  // Capture unvalidated, untrusted search query parameter
  const rawQuery = typeof req.query.q === 'string' ? req.query.q : '';

  // Render HTML with raw, unencoded query reflection (ROOT CAUSE OF XSS)
  const bodyContent = renderVulnerablePage(rawQuery);

  const html = renderLayout({
    title: 'Vulnerable Implementation',
    activeMode: 'vulnerable',
    bodyContent
  });

  // Explicitly set text/html content-type and send unencoded response
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.setHeader('X-XSS-Protection', '0'); // Disable legacy browser XSS filters for clean demonstration
  res.status(200).send(html);
}

// Mount GET /vulnerable
router.get('/', handleVulnerableSearch);

module.exports = router;
