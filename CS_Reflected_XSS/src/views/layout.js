/**
 * Base HTML Layout Shell
 * Provides a clean, modern, responsive cybersecurity dashboard layout.
 */

function renderLayout({ title, activeMode, bodyContent }) {
  // activeMode can be 'home', 'vulnerable', or 'secure'
  const isVulnerable = activeMode === 'vulnerable';
  const isSecure = activeMode === 'secure';

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${title} | Reflected XSS Security Lab</title>
  <link rel="stylesheet" href="/css/style.css">
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;700&family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
</head>
<body class="theme-cyber">
  <header class="app-header">
    <div class="header-container">
      <div class="brand">
        <span class="brand-shield">🛡️</span>
        <div class="brand-text">
          <span class="brand-title">Reflected XSS Security Lab</span>
          <span class="brand-subtitle">Web Server Security Laboratory</span>
        </div>
      </div>
      <nav class="nav-links">
        <a href="/" class="nav-link ${activeMode === 'home' ? 'active' : ''}">Overview</a>
        <a href="/vulnerable" class="nav-link nav-vulnerable ${isVulnerable ? 'active' : ''}">
          <span class="indicator-dot red"></span> Vulnerable Route
        </a>
        <a href="/secure" class="nav-link nav-secure ${isSecure ? 'active' : ''}">
          <span class="indicator-dot green"></span> Secured Route
        </a>
      </nav>
    </div>
  </header>

  <main class="main-content">
    ${bodyContent}
  </main>

  <footer class="app-footer">
    <div class="footer-container">
      <div class="footer-notice">
        <strong>⚠️ Security Notice:</strong> This laboratory environment is configured strictly for controlled vulnerability demonstration and analysis.
        The vulnerable route is isolated and bound strictly to <code>127.0.0.1</code>. Do not deploy publicly.
      </div>
      <div class="footer-meta">
        Reflected XSS Demonstration Dashboard • Node.js & Express • Localhost Only
      </div>
    </div>
  </footer>

  <script>
    window.LAB_PAYLOADS = {
      '1': "<script>alert('Reflected XSS Detected!')<\\/script>",
      '2': '<img src=x onerror="alert(\\'Reflected XSS via img onerror\\')">',
      '3': 'Network Security Fundamentals 2026'
    };

    window.loadPayload = function(triggerEl, payloadId) {
      var searchInput = document.getElementById('searchInput');
      if (!searchInput) return;

      var payload = window.LAB_PAYLOADS[payloadId];
      if (!payload && triggerEl && triggerEl.getAttribute) {
        var id = triggerEl.getAttribute('data-payload-id');
        payload = window.LAB_PAYLOADS[id] || triggerEl.getAttribute('data-payload');
      }

      if (payload) {
        searchInput.value = payload;
        searchInput.focus();
        if (searchInput.form) {
          searchInput.form.submit();
        }
      }
    };

    window.clearPayload = function() {
      var searchInput = document.getElementById('searchInput');
      if (searchInput) {
        searchInput.value = '';
        searchInput.focus();
      }
    };
  </script>
  <script src="/js/lab.js"></script>
</body>
</html>`;
}

module.exports = {
  renderLayout
};
