/**
 * Security and Educational Utilities for the Reflected XSS Lab
 */

/**
 * Context-appropriate HTML entity encoding function.
 * 
 * In HTML body and attribute contexts, untrusted input must be encoded
 * to prevent browsers from parsing user-supplied strings as HTML tags,
 * attributes, or script execution triggers.
 * 
 * Character mappings (OWASP recommendation):
 *  &  ->  &amp;   (Must be encoded first to prevent double-encoding)
 *  <  ->  &lt;    (Prevents opening new HTML tags like <script>, <img>, <iframe>)
 *  >  ->  &gt;    (Prevents closing existing tags or element injection)
 *  "  ->  &quot;  (Prevents attribute breakout when attributes use double quotes)
 *  '  ->  &#39;   (Prevents attribute breakout when attributes use single quotes)
 * 
 * @param {string} str - Raw untrusted input
 * @returns {string} - Escaped safe string for HTML text and quoted attribute contexts
 */
function encodeHTML(str) {
  if (typeof str !== 'string') {
    return '';
  }
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

/**
 * Educational definitions explaining XSS concepts and defense mechanisms.
 */
const educationalContent = {
  xssOverview: {
    title: "What is Reflected Cross-Site Scripting (XSS)?",
    content: "Reflected XSS (also known as Type-I or Non-Persistent XSS) occurs when an application receives untrusted data in an HTTP request (such as a URL query parameter or form submission) and immediately includes that data in the immediate HTTP response without adequate validation, filtering, or contextual output encoding. Because the payload is not stored on the server database, the victim must be persuaded to click an attacker-crafted link containing the malicious script."
  },
  rootCause: {
    title: "Exact Root Cause in the Vulnerable Code",
    summary: "The vulnerable route uses direct string concatenation/interpolation (template literals) to embed the raw query parameter `req.query.q` directly into the HTML response body and attribute contexts.",
    explanation: "When an attacker injects characters like `<` and `>`, the browser's HTML parser interprets them as HTML markup and script tags rather than plain text data. The browser cannot distinguish between trusted developer code and untrusted user input."
  },
  mitigationExplanation: {
    title: "How HTML Output Encoding Mitigates the Vulnerability",
    summary: "The secured route applies HTML entity encoding (`encodeHTML`) to the untrusted parameter before injecting it into the HTML template.",
    explanation: "By translating characters like `<` into `&lt;` and `>` into `&gt;`, the browser parser treats the characters as literal printable glyphs rather than executable markup delimiters. The browser stays in 'data' parsing mode and never switches into 'code execution' mode."
  },
  alternativeMitigations: [
    {
      name: "1. Framework Auto-Escaping (e.g. React, Angular, EJS <%= %>)",
      howItWorks: "Modern templating engines and UI frameworks automatically encode variables interpolated into HTML elements by default.",
      limitations: "Can be accidentally bypassed using raw unescaped directives (e.g. `<%-` in EJS, `v-html` in Vue, `dangerouslySetInnerHTML` in React) or when placing data inside dangerous contexts like `<script>` tags or `href='javascript:...'`."
    },
    {
      name: "2. HTML Sanitization (e.g. DOMPurify, sanitize-html)",
      howItWorks: "Parses and strips dangerous tags (like `<script>`) and attributes (like `onerror`) while allowing benign formatting (e.g. `<b>`, `<i>`).",
      limitations: "Complex to configure correctly. Risk of mutation XSS (mXSS) where the sanitizer and browser interpret nested HTML differently. Slower performance than simple output encoding."
    },
    {
      name: "3. Content Security Policy (CSP)",
      howItWorks: "An HTTP response header (e.g. `Content-Security-Policy: default-src 'self'`) that restricts the sources from which scripts can be executed and blocks inline script execution by default.",
      limitations: "Defense-in-depth only. Does not fix the underlying vulnerability. Complex to configure without breaking existing inline scripts. Misconfigurations (such as `'unsafe-inline'`) render it ineffective."
    },
    {
      name: "4. HttpOnly Cookies",
      howItWorks: "Setting the `HttpOnly` flag on session cookies prevents client-side JavaScript (`document.cookie`) from accessing the session identifier.",
      limitations: "Only protects cookie confidentiality. Does not prevent XSS from performing unauthorized actions (sending authenticated requests via fetch, defacing the page, capturing keystrokes)."
    },
    {
      name: "5. Safe Client-Side DOM Sinks",
      howItWorks: "Using `element.textContent` instead of `element.innerHTML` when manipulating the DOM via JavaScript.",
      limitations: "Only protects against client-side DOM-based XSS. Server-side reflected XSS returns malicious markup directly from the web server before any client-side JavaScript runs."
    }
  ]
};

module.exports = {
  encodeHTML,
  educationalContent
};
