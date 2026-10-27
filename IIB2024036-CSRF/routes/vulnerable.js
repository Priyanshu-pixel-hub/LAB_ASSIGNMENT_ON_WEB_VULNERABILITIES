/**
 * routes/vulnerable.js
 * 
 * ============================================================================
 * EDUCATIONAL SECURITY LAB - VULNERABLE IMPLEMENTATION
 * ============================================================================
 * Assigned Vulnerability: Cross-Site Request Forgery (CSRF)
 * Variant: 1 - GET-Based Forged Action
 * 
 * INTENTIONAL SECURITY DESIGN FLAW (FOR LAB DEMONSTRATION ONLY):
 * ----------------------------------------------------------------------------
 * 1. State-Changing GET Endpoint:
 *    According to RFC 7231 (HTTP/1.1), HTTP GET requests must be "safe" and
 *    "idempotent" (i.e., used only to retrieve information, never to modify
 *    server state). This route violates that fundamental semantic by mutating
 *    the student's registered email address through an HTTP GET request.
 * 
 * 2. Reliance on Ambient Authority (Session Cookies):
 *    Web browsers automatically include session cookies (ambient credentials)
 *    in cross-site requests (e.g., triggered by <img>, <a>, <script>, or <iframe>
 *    on a third-party malicious website).
 * 
 * 3. Absence of Intent Verification (No Anti-CSRF Token):
 *    The server verifies that the user is logged in (session exists), but does
 *    NOT verify that the user INTENDED to make this specific state-changing
 *    request. An attacker can trick the victim's browser into executing this
 *    request transparently without the victim's knowledge or consent.
 * 
 * WARNING:
 * This code is strictly for local educational demonstration in an academic lab.
 * Never use state-changing GET endpoints or un-tokenized mutations in production.
 * ============================================================================
 */

const express = require("express");
const router = express.Router();
const {
  requireAuth,
  getStudent,
  updateStudentEmail,
  getLabMode
} = require("../middleware/authentication");
const { logLabAudit } = require("../middleware/auditLogger");

/**
 * GET /api/vulnerable/change-email
 * 
 * VULNERABLE ENDPOINT:
 * Changes the student's email address using a simple GET request.
 * 
 * Query Parameter:
 *   ?email=<new-email-address>
 */
router.get("/change-email", requireAuth, (req, res) => {
  const mode = getLabMode();
  const newEmail = req.query.email;

  // Check if server is currently running in Secure Mode
  if (mode === "secure") {
    res.set("Allow", "POST");

    logLabAudit({
      endpoint: "/api/vulnerable/change-email",
      method: "GET",
      authenticated: true,
      csrfValidation: "N/A (Method rejected)",
      emailChanged: "NO (Rejected with 405 Method Not Allowed — Secure Mode Policy)"
    });

    if (req.headers.accept && req.headers.accept.includes("text/html") && !req.headers.accept.includes("application/json")) {
      return res.status(405).send(`
        <!DOCTYPE html>
        <html lang="en">
        <head>
          <meta charset="UTF-8">
          <title>405 Method Not Allowed — Secure Mode Active</title>
          <link rel="stylesheet" href="/styles.css">
        </head>
        <body class="lab-body">
          <div class="result-card safe-card">
            <div class="card-header">
              <span class="badge safe-badge">HTTP 405 METHOD NOT ALLOWED</span>
              <h2>GET-Based Attack Prohibited</h2>
            </div>
            <div class="card-body">
              <p><strong>Secure Mode Policy Enforced (RFC 7231):</strong></p>
              <p>The Student Portal is running in <strong>SECURE MODE</strong>. State-changing GET requests are rejected. State mutations require HTTP POST accompanied by a valid CSRF synchronizer token.</p>
              <div class="audit-box">
                <p><strong>Current Email:</strong> <span>${getStudent().email}</span> (Unchanged)</p>
                <p><strong>Allowed Method:</strong> POST /api/secure/change-email with valid 'x-csrf-token'</p>
              </div>
              <div class="button-group">
                <a href="/dashboard" class="btn btn-primary">Return to Student Dashboard</a>
              </div>
            </div>
          </div>
        </body>
        </html>
      `);
    }

    return res.status(405).json({
      success: false,
      error: "Method Not Allowed",
      message: "HTTP GET requests cannot modify application state in Secure Mode. In compliance with RFC 7231, state changes require HTTP POST with a valid CSRF synchronizer token.",
      labMode: mode,
      currentEmail: getStudent().email,
      allow: "POST"
    });
  }

  // Validate that an email query parameter was provided
  if (!newEmail || typeof newEmail !== "string" || !newEmail.trim()) {
    logLabAudit({
      endpoint: "/api/vulnerable/change-email",
      method: "GET",
      authenticated: true,
      csrfValidation: "N/A",
      emailChanged: "NO (400 Missing email parameter)"
    });

    return res.status(400).json({
      success: false,
      error: "Missing parameter",
      message: "Query parameter 'email' is required (e.g., ?email=newemail@example.com)."
    });
  }

  const trimmedEmail = newEmail.trim();

  // Basic format validation (intentionally simple)
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(trimmedEmail)) {
    logLabAudit({
      endpoint: "/api/vulnerable/change-email",
      method: "GET",
      authenticated: true,
      csrfValidation: "N/A",
      emailChanged: "NO (400 Invalid email format)"
    });

    return res.status(400).json({
      success: false,
      error: "Invalid email format",
      message: "The provided email address does not follow standard email syntax."
    });
  }

  // ==========================================================================
  // FLAW IN ACTION:
  // Mutating server state using a GET request without an anti-CSRF token!
  // The browser automatically attached the student's session cookie, so the
  // server blindly trusts this request originated intentionally from the student.
  // ==========================================================================
  const { previousEmail, currentEmail } = updateStudentEmail(trimmedEmail);

  // Also update session user email cache
  if (req.session.user) {
    req.session.user.email = currentEmail;
  }

  logLabAudit({
    endpoint: "/api/vulnerable/change-email",
    method: "GET",
    authenticated: true,
    csrfValidation: "N/A (VULNERABILITY: No CSRF token verified!)",
    emailChanged: `YES (${previousEmail} -> ${currentEmail})`
  });

  // If request accepts HTML (e.g. if victim clicked a link or was redirected),
  // return an informative response page, otherwise JSON.
  if (req.headers.accept && req.headers.accept.includes("text/html") && !req.headers.accept.includes("application/json")) {
    return res.send(`
      <!DOCTYPE html>
      <html lang="en">
      <head>
        <meta charset="UTF-8">
        <title>Vulnerable CSRF Exploit Succeeded</title>
        <link rel="stylesheet" href="/styles.css">
      </head>
      <body class="lab-body">
        <div class="result-card danger-card">
          <div class="card-header">
            <span class="badge danger-badge">EXPLOIT SUCCESSFUL</span>
            <h2>GET-Based CSRF Triggered</h2>
          </div>
          <div class="card-body">
            <p><strong>Intentional Vulnerability Demonstrated:</strong></p>
            <p>The student email address was silently changed via an ambient HTTP GET request!</p>
            <div class="audit-box">
              <p><strong>Previous Email:</strong> <span class="strikethrough">${previousEmail}</span></p>
              <p><strong>New Compromised Email:</strong> <span class="highlight-danger">${currentEmail}</span></p>
              <p><strong>Victim Session:</strong> Valid student session cookie was automatically sent by your browser.</p>
              <p><strong>User Intent Check:</strong> None performed by server.</p>
            </div>
            <div class="button-group">
              <a href="/dashboard" class="btn btn-primary">Return to Student Dashboard</a>
              <a href="/csrf-lab" class="btn btn-secondary">Open Security Lab Panel</a>
            </div>
          </div>
        </div>
      </body>
      </html>
    `);
  }

  // Standard JSON response
  return res.status(200).json({
    success: true,
    exploitStatus: "EXPLOIT_SUCCEEDED",
    vulnerability: "GET-Based CSRF (CWE-352)",
    message: "Email address changed successfully via GET request without anti-CSRF token verification.",
    details: {
      previousEmail,
      updatedEmail: currentEmail,
      attackVector: "HTTP GET /api/vulnerable/change-email?email=" + encodeURIComponent(trimmedEmail),
      authenticationType: "Session Cookie (Ambient Authority)",
      intentVerified: false
    }
  });
});

module.exports = router;
