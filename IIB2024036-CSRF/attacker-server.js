/**
 * attacker-server.js
 * 
 * ============================================================================
 * EDUCATIONAL SECURITY LAB — ATTACKER WEBSITE SERVER
 * ============================================================================
 * Simulates an untrusted third-party website running on a DIFFERENT ORIGIN
 * from the Apex University Student Portal.
 * 
 * Origin: http://localhost:4000 (Cross-Origin from Portal on http://localhost:3000)
 * 
 * ROLE IN CSRF ATTACK DEMONSTRATION:
 * 1. Serves a simulated attacker-controlled webpage (e.g. malicious forum, blog, or phishing landing page).
 * 2. Demonstrates cross-origin GET requests targeting the Student Portal without user authorization.
 * 3. Operates strictly within browser Same-Origin Policy (SOP) boundaries:
 *    - Does NOT have access to Student Portal DOM or localStorage.
 *    - Cannot read Student Portal cookies (HttpOnly protects against JS read; cross-origin prevents access).
 *    - Cannot steal or predict synchronizer CSRF tokens.
 * 4. Dispatches genuine browser requests rather than fabricated client results.
 * ============================================================================
 */

const express = require("express");
const path = require("path");

const app = express();
const PORT = process.env.ATTACKER_PORT || process.env.PORT || 4000;
const TARGET_PORTAL = process.env.PORTAL_URL || "http://localhost:3000";

// Basic parsing if needed
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Serve static attacker site assets (CSS, images, JS)
app.use(express.static(path.join(__dirname, "attacker")));

// Configuration endpoint so frontend dynamically knows the target portal URL
app.get("/api/config", (req, res) => {
  res.json({
    attackerOrigin: `http://localhost:${PORT}`,
    targetPortalUrl: TARGET_PORTAL,
    environment: "Localhost Educational Cybersecurity Lab"
  });
});

// Root route: Serve attacker lab page
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "attacker", "index.html"));
});

// Health check endpoint for automated test validation
app.get("/health", (req, res) => {
  res.json({
    status: "ok",
    service: "csrf-attacker-server",
    origin: `http://localhost:${PORT}`,
    targetPortal: TARGET_PORTAL
  });
});

if (require.main === module) {
  app.listen(PORT, () => {
    console.log("================================================================");
    console.log("  ⚠️  ATTACKER DEMONSTRATION SERVER RUNNING (SIMULATED MALICIOUS SITE)");
    console.log(`  URL: http://localhost:${PORT}`);
    console.log(`  Target Student Portal: ${TARGET_PORTAL}`);
    console.log("  Security Boundary: Distinct Origin (Different Port & Service)");
    console.log("================================================================");
  });
}

module.exports = app;
