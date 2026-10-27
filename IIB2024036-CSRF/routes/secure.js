/**
 * routes/secure.js
 * 
 * ============================================================================
 * SECURE IMPLEMENTATION — SYNCHRONIZER TOKEN CSRF DEFENSE
 * ============================================================================
 * Assigned Vulnerability Mitigation:
 * 1. Method Enforcement:
 *    HTTP GET is strictly read-only and idempotent (returns 405 Method Not Allowed
 *    if invoked as a state-changing mutation).
 *    All state-changing updates require HTTP POST.
 * 
 * 2. Cryptographic Synchronizer Anti-CSRF Token:
 *    A cryptographically random token (generated using crypto.randomBytes(32))
 *    is tied to the authenticated user's session.
 * 
 * 3. Strict Server-Side Validation:
 *    Every state-changing POST request must supply the token via request header
 *    ('x-csrf-token') or request body ('csrf_token'). The server verifies the token
 *    using timing-safe comparison (crypto.timingSafeEqual) before mutating state.
 * 
 * 4. Ambient Authority Defense:
 *    Even if a third-party site tricks the browser into sending a POST request
 *    with the session cookie, the attacker cannot read or guess the unpredictable
 *    synchronizer token (due to Same-Origin Policy), causing the attack to fail.
 * ============================================================================
 */

const express = require("express");
const crypto = require("crypto");
const router = express.Router();
const {
  requireAuth,
  getStudent,
  updateStudentEmail
} = require("../middleware/authentication");
const { generateCsrfToken } = require("./auth");
const { logLabAudit } = require("../middleware/auditLogger");

/**
 * Middleware: Verify CSRF Synchronizer Token
 * Ensures that the request contains a valid token that matches the session token.
 */
function verifyCsrfToken(req, res, next) {
  // Retrieve token from request header or body
  const clientToken = req.headers["x-csrf-token"] || (req.body && req.body.csrf_token);
  const sessionToken = req.session && req.session.csrfToken;

  // 1. Check if token is provided in the request
  if (!clientToken || typeof clientToken !== "string") {
    logLabAudit({
      endpoint: "/api/secure/change-email",
      method: req.method,
      authenticated: Boolean(req.session && req.session.user),
      csrfValidation: "FAILED (CSRF_TOKEN_MISSING)",
      emailChanged: "NO (Rejected with 403 Forbidden)"
    });

    if (req.headers.accept && req.headers.accept.includes("text/html") && !req.headers.accept.includes("application/json")) {
      return res.status(403).send(`
        <!DOCTYPE html>
        <html lang="en">
        <head>
          <meta charset="UTF-8">
          <title>403 Forbidden — CSRF Token Missing</title>
          <link rel="stylesheet" href="/styles.css">
        </head>
        <body class="lab-body">
          <div class="result-card safe-card">
            <div class="card-header">
              <span class="badge safe-badge">403 FORBIDDEN — DEFENSE ACTIVE</span>
              <h2>CSRF Synchronizer Token Missing</h2>
            </div>
            <div class="card-body">
              <p><strong>Security Violation Prevented:</strong></p>
              <p>The state-changing request was submitted without an anti-CSRF synchronizer token. Cross-site attacker pages cannot supply this token due to the Same-Origin Policy.</p>
              <div class="audit-box">
                <p><strong>Current Email:</strong> <span>${getStudent().email}</span> (Unchanged)</p>
                <p><strong>Defense Mechanism:</strong> Synchronizer Token Pattern (OWASP recommendation)</p>
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

    return res.status(403).json({
      success: false,
      error: "CSRF token missing",
      message: "Security violation: Missing anti-CSRF synchronizer token. The state-changing request was rejected.",
      securityCode: "CSRF_TOKEN_MISSING"
    });
  }

  // 2. Check if a valid session token exists
  if (!sessionToken || typeof sessionToken !== "string") {
    logLabAudit({
      endpoint: "/api/secure/change-email",
      method: req.method,
      authenticated: Boolean(req.session && req.session.user),
      csrfValidation: "FAILED (SESSION_TOKEN_ABSENT)",
      emailChanged: "NO (Rejected with 403 Forbidden)"
    });

    return res.status(403).json({
      success: false,
      error: "Session CSRF token not found",
      message: "Security violation: No active anti-CSRF token associated with current session.",
      securityCode: "SESSION_TOKEN_ABSENT"
    });
  }

  // 3. Timing-safe comparison to prevent side-channel timing attacks
  const clientBuffer = Buffer.from(clientToken, "utf8");
  const sessionBuffer = Buffer.from(sessionToken, "utf8");

  if (clientBuffer.length !== sessionBuffer.length || !crypto.timingSafeEqual(clientBuffer, sessionBuffer)) {
    logLabAudit({
      endpoint: "/api/secure/change-email",
      method: req.method,
      authenticated: Boolean(req.session && req.session.user),
      csrfValidation: "FAILED (CSRF_TOKEN_MISMATCH)",
      emailChanged: "NO (Rejected with 403 Forbidden)"
    });

    if (req.headers.accept && req.headers.accept.includes("text/html") && !req.headers.accept.includes("application/json")) {
      return res.status(403).send(`
        <!DOCTYPE html>
        <html lang="en">
        <head>
          <meta charset="UTF-8">
          <title>403 Forbidden — Invalid CSRF Token</title>
          <link rel="stylesheet" href="/styles.css">
        </head>
        <body class="lab-body">
          <div class="result-card safe-card">
            <div class="card-header">
              <span class="badge safe-badge">403 FORBIDDEN — DEFENSE ACTIVE</span>
              <h2>CSRF Token Mismatch / Tampered</h2>
            </div>
            <div class="card-body">
              <p><strong>Security Violation Prevented:</strong></p>
              <p>The provided anti-CSRF token does not match the active session synchronizer token.</p>
              <div class="audit-box">
                <p><strong>Current Email:</strong> <span>${getStudent().email}</span> (Unchanged)</p>
                <p><strong>Verification:</strong> Timing-safe constant-time comparison (crypto.timingSafeEqual)</p>
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

    return res.status(403).json({
      success: false,
      error: "Invalid CSRF token",
      message: "Security violation: Provided anti-CSRF token is invalid or does not match the active session.",
      securityCode: "CSRF_TOKEN_MISMATCH"
    });
  }

  // Token is valid; proceed to handler
  return next();
}

/**
 * GET /api/secure/csrf-token
 * Provides the legitimate client application with the active session CSRF token.
 */
router.get("/csrf-token", requireAuth, (req, res) => {
  if (!req.session.csrfToken) {
    req.session.csrfToken = generateCsrfToken();
  }

  return res.status(200).json({
    success: true,
    csrfToken: req.session.csrfToken
  });
});

/**
 * GET /api/secure/change-email
 * 
 * MITIGATION EVIDENCE:
 * Rejects GET requests attempting to alter email state.
 * Adheres to HTTP semantics (GET is safe & idempotent).
 */
router.get("/change-email", requireAuth, (req, res) => {
  res.set("Allow", "POST");

  logLabAudit({
    endpoint: "/api/secure/change-email",
    method: "GET",
    authenticated: Boolean(req.session && req.session.user),
    csrfValidation: "N/A (Method rejected)",
    emailChanged: "NO (Rejected with 405 Method Not Allowed)"
  });

  if (req.headers.accept && req.headers.accept.includes("text/html") && !req.headers.accept.includes("application/json")) {
    return res.status(405).send(`
      <!DOCTYPE html>
      <html lang="en">
      <head>
        <meta charset="UTF-8">
        <title>405 Method Not Allowed — Secure Endpoint</title>
        <link rel="stylesheet" href="/styles.css">
      </head>
      <body class="lab-body">
        <div class="result-card safe-card">
          <div class="card-header">
            <span class="badge safe-badge">HTTP 405 METHOD NOT ALLOWED</span>
            <h2>GET Method Prohibited for State Mutations</h2>
          </div>
          <div class="card-body">
            <p><strong>HTTP Semantics Adherence (RFC 7231):</strong></p>
            <p>HTTP GET requests must be safe and idempotent. They must never alter application state. In our secure architecture, state changes strictly require HTTP POST accompanied by a valid CSRF synchronizer token.</p>
            <div class="audit-box">
              <p><strong>Current Email:</strong> <span>${getStudent().email}</span> (Unchanged)</p>
              <p><strong>Enforced Requirement:</strong> POST /api/secure/change-email with valid 'x-csrf-token'</p>
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
    message: "HTTP GET requests cannot modify application state. In compliance with RFC 7231, state-changing operations require HTTP POST with a valid CSRF synchronizer token.",
    currentEmail: getStudent().email,
    remedy: "Submit a POST request to /api/secure/change-email with a valid 'x-csrf-token' header or 'csrf_token' field."
  });
});

/**
 * POST /api/secure/change-email
 * 
 * SECURED ENDPOINT:
 * Changes student email using HTTP POST protected by Synchronizer Token Pattern.
 */
router.post("/change-email", requireAuth, verifyCsrfToken, (req, res) => {
  const { email } = req.body;

  if (!email || typeof email !== "string" || !email.trim()) {
    logLabAudit({
      endpoint: "/api/secure/change-email",
      method: "POST",
      authenticated: true,
      csrfValidation: "PASSED",
      emailChanged: "NO (400 Missing email parameter)"
    });

    return res.status(400).json({
      success: false,
      error: "Missing parameter",
      message: "Field 'email' is required in request body."
    });
  }

  const trimmedEmail = email.trim();

  // Validate email format
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(trimmedEmail)) {
    logLabAudit({
      endpoint: "/api/secure/change-email",
      method: "POST",
      authenticated: true,
      csrfValidation: "PASSED",
      emailChanged: "NO (400 Invalid email format)"
    });

    return res.status(400).json({
      success: false,
      error: "Invalid email format",
      message: "The provided email address does not follow standard email syntax."
    });
  }

  // Update in-memory state
  const { previousEmail, currentEmail } = updateStudentEmail(trimmedEmail);

  if (req.session.user) {
    req.session.user.email = currentEmail;
  }

  // Defense-in-depth: Rotate CSRF token after successful state change
  req.session.csrfToken = generateCsrfToken();

  logLabAudit({
    endpoint: "/api/secure/change-email",
    method: "POST",
    authenticated: true,
    csrfValidation: "PASSED",
    emailChanged: `YES (${previousEmail} -> ${currentEmail})`
  });

  return res.status(200).json({
    success: true,
    message: "Email address updated successfully using protected POST with valid CSRF token.",
    previousEmail,
    currentEmail,
    newCsrfToken: req.session.csrfToken
  });
});

module.exports = router;
module.exports.verifyCsrfToken = verifyCsrfToken;
