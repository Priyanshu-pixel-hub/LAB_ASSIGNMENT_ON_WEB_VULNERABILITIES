/**
 * ============================================================================
 * SECURED ROUTE MODULE (MITIGATED IMPLEMENTATION)
 * ============================================================================
 * Demonstrates the industry standard mitigation for Reflected XSS in an HTML
 * body and attribute context: Context-Appropriate Output Encoding.
 * ============================================================================
 */

const express = require('express');
const router = express.Router();
const { renderLayout } = require('../views/layout');
const { renderSecurePage } = require('../views/pages');

/**
 * Isolated Secured Handler Function
 * 
 * TECHNICAL IMPLEMENTATION BREAKDOWN:
 * In this function:
 * 1. `req.query.q` captures untrusted user input from the URL query string.
 * 2. Unlike the vulnerable route, input is processed exclusively through `renderSecurePage(query)`.
 * 3. Inside `renderSecurePage`, the query is passed through `encodeHTML(query)`.
 * 4. The characters &, <, >, ", and ' are converted to &amp;, &lt;, &gt;, &quot;, and &#39;.
 * 5. When the browser receives this response, the HTML parser stays in text-rendering mode,
 *    displaying the payload as literal characters on screen rather than executing it.
 */
function handleSecureSearch(req, res) {
  // Capture search query parameter
  const rawQuery = typeof req.query.q === 'string' ? req.query.q : '';

  // Render HTML using isolated secure page renderer with context output encoding
  const bodyContent = renderSecurePage(rawQuery);

  const html = renderLayout({
    title: 'Secured Implementation',
    activeMode: 'secure',
    bodyContent
  });

  // Standard safe response headers
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.status(200).send(html);
}

// Mount GET /secure
router.get('/', handleSecureSearch);

module.exports = router;
