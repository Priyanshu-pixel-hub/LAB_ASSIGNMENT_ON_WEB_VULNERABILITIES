/**
 * Page Templates for Home, Vulnerable Lab, and Secured Lab
 */

const { encodeHTML, educationalContent } = require('./utils');

/**
 * Render the Landing / Overview Page
 */
function renderHomePage() {
  const content = `
    <div class="lab-container">
      <section class="hero-section">
        <div class="hero-badge">Web Server Security Lab</div>
        <h1 class="hero-title">Reflected Cross-Site Scripting (XSS)</h1>
        <p class="hero-desc">
          An interactive, side-by-side demonstration comparing an intentionally vulnerable implementation
          with an industry-standard secured implementation using contextual HTML entity encoding.
        </p>
      </section>

      <section class="mode-cards-grid">
        <div class="card card-vulnerable">
          <div class="card-status-badge badge-vulnerable">
            <span class="status-pulse red"></span> Vulnerable Route
          </div>
          <h2 class="card-title">1. Intentionally Vulnerable Lab</h2>
          <p class="card-text">
            Demonstrates how unencoded user-supplied GET parameter <code>q</code> is concatenated directly into
            the HTML response body. This enables the browser to parse input as executable markup.
          </p>
          <div class="code-preview">
            <div class="code-header">Vulnerable Server Logic</div>
            <pre><code>// Direct string concatenation without encoding
const results = '&lt;strong&gt;' + req.query.q + '&lt;/strong&gt;';
res.send(htmlTemplate(results));</code></pre>
          </div>
          <a href="/vulnerable" class="btn btn-danger">Open Vulnerable Lab &rarr;</a>
        </div>

        <div class="card card-secure">
          <div class="card-status-badge badge-secure">
            <span class="status-pulse green"></span> Secured Route
          </div>
          <h2 class="card-title">2. Secured Implementation Lab</h2>
          <p class="card-text">
            Demonstrates the primary defense against reflected XSS: contextual HTML entity encoding.
            Special characters such as <code>&lt;</code>, <code>&gt;</code>, <code>&amp;</code>, <code>&quot;</code>, and <code>&#39;</code> are converted to harmless HTML entities.
          </p>
          <div class="code-preview">
            <div class="code-header">Secured Server Logic</div>
            <pre><code>// Safe contextual HTML output encoding
const safeQuery = encodeHTML(req.query.q);
const results = '&lt;strong&gt;' + safeQuery + '&lt;/strong&gt;';
res.send(htmlTemplate(results));</code></pre>
          </div>
          <a href="/secure" class="btn btn-success">Open Secured Lab &rarr;</a>
        </div>
      </section>

      <section class="info-card">
        <h3 class="section-title">🧪 Educational Concept Overview</h3>
        <p class="lead-text">${educationalContent.xssOverview.content}</p>
        
        <div class="feature-comparison-table">
          <table>
            <thead>
              <tr>
                <th>Attribute</th>
                <th>Vulnerable Route (<code>/vulnerable</code>)</th>
                <th>Secured Route (<code>/secure</code>)</th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <td><strong>Input Processing</strong></td>
                <td>Raw <code>req.query.q</code> used directly</td>
                <td>Encoded through <code>encodeHTML()</code></td>
              </tr>
              <tr>
                <td><strong>HTML Parser Behavior</strong></td>
                <td>Interprets <code>&lt;script&gt;</code> as executable code</td>
                <td>Interprets <code>&amp;lt;script&amp;gt;</code> as plain text symbols</td>
              </tr>
              <tr>
                <td><strong>Test Payload Result</strong></td>
                <td>JavaScript alert pop-up executes in browser</td>
                <td>Payload displays harmlessly on screen as text</td>
              </tr>
              <tr>
                <td><strong>Recommended Use</strong></td>
                <td>Strictly isolated for local educational testing</td>
                <td>Production-safe standard for HTML body contexts</td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>
    </div>
  `;

  return content;
}

/**
 * Render the Vulnerable Demonstration Page
 * @param {string} query - Raw unescaped user query parameter
 */
function renderVulnerablePage(query) {
  const hasQuery = typeof query === 'string' && query.length > 0;

  // Intentionally Vulnerable Reflection:
  // query is interpolated directly into HTML text context and attribute context without encoding
  const resultsHtml = hasQuery
    ? `<div class="results-box vulnerable-results">
        <div class="results-meta">
          <span class="results-badge">Reflected Output (Unescaped)</span>
          <span class="results-warning">⚠️ Executable Context Active</span>
        </div>
        <p class="results-display">Search results for: <strong>${query}</strong></p>
        <div class="dom-inspector">
          <div class="inspector-label">Server-Generated Raw HTML Chunk:</div>
          <pre class="inspector-code"><code>&lt;p&gt;Search results for: &lt;strong&gt;${escapeForPreTag(query)}&lt;/strong&gt;&lt;/p&gt;</code></pre>
        </div>
      </div>`
    : `<div class="results-box empty-results">
        <p class="text-muted">Enter a search query above or load a test payload to trigger reflected output.</p>
      </div>`;

  return `
    <div class="lab-container">
      <div class="mode-header-bar bar-vulnerable">
        <div class="mode-indicator-group">
          <span class="mode-pill pill-danger">🔴 VULNERABLE ROUTE</span>
          <span class="mode-status-text">Intentionally Unencoded Server Reflection • Local Educational Use Only</span>
        </div>
        <div class="mode-actions">
          <a href="/secure${hasQuery ? '?q=' + encodeURIComponent(query) : ''}" class="btn btn-outline-success">
            Switch to Secured Implementation &rarr;
          </a>
        </div>
      </div>

      <div class="lab-grid">
        <div class="lab-main-col">
          <div class="card interactive-card">
            <h2 class="card-heading">Search Application Simulation</h2>
            <p class="card-subheading">
              This simulated search endpoint reflects your search term back into the response without HTML output encoding.
            </p>

            <form action="/vulnerable" method="GET" class="search-form">
              <div class="search-input-wrapper">
                <input 
                  type="text" 
                  name="q" 
                  id="searchInput" 
                  class="search-input" 
                  placeholder="Enter search term or select a test payload below..." 
                  value="${query || ''}"
                  autocomplete="off"
                >
                <button type="submit" class="btn btn-primary">Search</button>
              </div>
            </form>

            <div class="payload-loader-panel">
              <div class="loader-header">
                <span class="loader-label">Load Harmless Test Payloads:</span>
                <span id="payloadStatus" class="payload-status"></span>
              </div>
              <div class="loader-buttons">
                <button type="button" class="btn-chip" onclick="window.loadPayload(this, '1')" data-payload-id="1" data-payload="<script>alert('Reflected XSS Detected!')</script>">
                  <span>1</span> &lt;script&gt; Tag Alert
                </button>
                <button type="button" class="btn-chip" onclick="window.loadPayload(this, '2')" data-payload-id="2" data-payload="<img src=x onerror=&quot;alert('Reflected XSS via img onerror')&quot;>">
                  <span>2</span> &lt;img onerror&gt; Event Alert
                </button>
                <button type="button" class="btn-chip" onclick="window.loadPayload(this, '3')" data-payload-id="3" data-payload="Network Security Fundamentals 2026">
                  <span>3</span> Normal Search String
                </button>
                <button type="button" class="btn-chip btn-chip-clear" onclick="window.clearPayload()" id="clearBtn">
                  Clear
                </button>
              </div>
            </div>

            <div class="results-section">
              <h3 class="results-title">Search Output Section</h3>
              ${resultsHtml}
            </div>
          </div>
        </div>

        <aside class="lab-sidebar-col">
          <div class="card explanation-card border-vulnerable">
            <h3 class="explanation-title text-danger">⚠️ Root Cause Analysis</h3>
            <p class="explanation-desc">
              <strong>${educationalContent.rootCause.summary}</strong>
            </p>
            <div class="code-snippet-box">
              <div class="snippet-header">vulnerable.js (Lines demonstrating flaw)</div>
              <pre><code>// 1. Extract untrusted parameter from GET query
const query = req.query.q || '';

// 2. ROOT CAUSE: Direct interpolation without encoding
const results = \`&lt;strong&gt;\${query}&lt;/strong&gt;\`;

// 3. Send raw string to client browser
res.send(renderPage(results));</code></pre>
            </div>
            <p class="explanation-text">
              ${educationalContent.rootCause.explanation}
            </p>
            <div class="callout callout-warning">
              <strong>Key Security Finding:</strong> The application fails to separate data from code instructions. By reflecting raw input directly into the HTML response, the browser DOM parser executes malicious script tags within the origin's session context.
            </div>
          </div>
        </aside>
      </div>
    </div>
  `;
}

/**
 * Render the Secured Demonstration Page
 * @param {string} query - Raw user query parameter (encoded safely on output)
 */
function renderSecurePage(query) {
  const hasQuery = typeof query === 'string' && query.length > 0;
  
  // Safe HTML Output Encoding
  const safeQuery = encodeHTML(query || '');

  const resultsHtml = hasQuery
    ? `<div class="results-box secure-results">
        <div class="results-meta">
          <span class="results-badge badge-safe">Output Safely Encoded</span>
          <span class="results-indicator">🛡️ Contextual HTML Entity Encoding Active</span>
        </div>
        <p class="results-display">Search results for: <strong>${safeQuery}</strong></p>
        <div class="dom-inspector">
          <div class="inspector-label">Server-Generated Safe HTML Entity Representation:</div>
          <pre class="inspector-code"><code>&lt;p&gt;Search results for: &lt;strong&gt;${escapeForPreTag(safeQuery)}&lt;/strong&gt;&lt;/p&gt;</code></pre>
        </div>
      </div>`
    : `<div class="results-box empty-results">
        <p class="text-muted">Enter a search query above or load a test payload to verify literal rendering.</p>
      </div>`;

  return `
    <div class="lab-container">
      <div class="mode-header-bar bar-secure">
        <div class="mode-indicator-group">
          <span class="mode-pill pill-success">🟢 SECURED ROUTE</span>
          <span class="mode-status-text">Mitigated via Context-Appropriate HTML Entity Encoding</span>
        </div>
        <div class="mode-actions">
          <a href="/vulnerable${hasQuery ? '?q=' + encodeURIComponent(query) : ''}" class="btn btn-outline-danger">
            Switch to Vulnerable Implementation &rarr;
          </a>
        </div>
      </div>

      <div class="lab-grid">
        <div class="lab-main-col">
          <div class="card interactive-card">
            <h2 class="card-heading">Secured Search Simulation</h2>
            <p class="card-subheading">
              This secured endpoint accepts identical search queries and payloads, but applies RFC/OWASP-compliant HTML output encoding before rendering.
            </p>

            <form action="/secure" method="GET" class="search-form">
              <div class="search-input-wrapper">
                <input 
                  type="text" 
                  name="q" 
                  id="searchInput" 
                  class="search-input" 
                  placeholder="Enter search term or select a test payload below..." 
                  value="${safeQuery}"
                  autocomplete="off"
                >
                <button type="submit" class="btn btn-success">Search</button>
              </div>
            </form>

            <div class="payload-loader-panel">
              <div class="loader-header">
                <span class="loader-label">Load Harmless Test Payloads:</span>
                <span id="payloadStatus" class="payload-status"></span>
              </div>
              <div class="loader-buttons">
                <button type="button" class="btn-chip" onclick="window.loadPayload(this, '1')" data-payload-id="1" data-payload="<script>alert('Reflected XSS Detected!')</script>">
                  <span>1</span> &lt;script&gt; Tag Alert
                </button>
                <button type="button" class="btn-chip" onclick="window.loadPayload(this, '2')" data-payload-id="2" data-payload="<img src=x onerror=&quot;alert('Reflected XSS via img onerror')&quot;>">
                  <span>2</span> &lt;img onerror&gt; Event Alert
                </button>
                <button type="button" class="btn-chip" onclick="window.loadPayload(this, '3')" data-payload-id="3" data-payload="Network Security Fundamentals 2026">
                  <span>3</span> Normal Search String
                </button>
                <button type="button" class="btn-chip btn-chip-clear" onclick="window.clearPayload()" id="clearBtn">
                  Clear
                </button>
              </div>
            </div>

            <div class="results-section">
              <h3 class="results-title">Search Output Section</h3>
              ${resultsHtml}
            </div>
          </div>

          <!-- Comprehensive Alternative Mitigations Table -->
          <div class="card defense-matrix-card">
            <h3 class="section-title">🛡️ Defense-in-Depth: Mitigation Alternatives & Limitations</h3>
            <p class="section-subtitle">
              Comparison between the primary mitigation implemented here (HTML Output Encoding) and alternative industry security controls.
            </p>
            <div class="matrix-list">
              ${educationalContent.alternativeMitigations.map(m => `
                <div class="matrix-item">
                  <h4 class="matrix-name">${m.name}</h4>
                  <div class="matrix-grid">
                    <div class="matrix-how">
                      <span class="sub-label">How it works:</span> ${m.howItWorks}
                    </div>
                    <div class="matrix-limit">
                      <span class="sub-label text-warning">Limitations:</span> ${m.limitations}
                    </div>
                  </div>
                </div>
              `).join('')}
            </div>
          </div>
        </div>

        <aside class="lab-sidebar-col">
          <div class="card explanation-card border-secure">
            <h3 class="explanation-title text-success">🛡️ Mitigation Mechanism</h3>
            <p class="explanation-desc">
              <strong>${educationalContent.mitigationExplanation.summary}</strong>
            </p>
            <div class="code-snippet-box">
              <div class="snippet-header">secure.js & utils.js (Applied Mitigation)</div>
              <pre><code>// 1. Context-appropriate entity encoder
function encodeHTML(str) {
  return String(str)
    .replace(/&/g, '&amp;amp;')
    .replace(/&lt;/g, '&amp;lt;')
    .replace(/&gt;/g, '&amp;gt;')
    .replace(/"/g, '&amp;quot;')
    .replace(/'/g, '&amp;#39;');
}

// 2. Encode untrusted input BEFORE interpolation
const safeQuery = encodeHTML(req.query.q || '');
const results = \`&lt;strong&gt;\${safeQuery}&lt;/strong&gt;\`;</code></pre>
            </div>
            <p class="explanation-text">
              ${educationalContent.mitigationExplanation.explanation}
            </p>
            <div class="callout callout-info">
              <strong>Context Sensitivity Rule:</strong> Output encoding must match the exact document context. While HTML entity encoding secures standard body text, user input placed inside script blocks or URL schemes requires dedicated JavaScript or URI encoding.
            </div>
          </div>
        </aside>
      </div>
    </div>
  `;
}

/**
 * Helper to escape characters for display inside an inspector <pre> block
 * so HTML doesn't render prematurely.
 */
function escapeForPreTag(str) {
  if (typeof str !== 'string') return '';
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

module.exports = {
  renderHomePage,
  renderVulnerablePage,
  renderSecurePage
};
