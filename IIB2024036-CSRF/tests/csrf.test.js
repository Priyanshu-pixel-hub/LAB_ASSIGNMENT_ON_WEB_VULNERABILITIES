/**
 * tests/csrf.test.js
 * 
 * Automated Security Verification Test Suite
 * Evaluates backend endpoints for CSRF vulnerability exploitation,
 * synchronizer token enforcement, HTTP method semantics, input validation,
 * and session lifecycle integrity.
 */

const { describe, it, beforeEach } = require("node:test");
const assert = require("node:assert/strict");
const request = require("supertest");
const app = require("../server");
const attackerApp = require("../attacker-server");
const { resetStudentData, setLabMode, getStudent } = require("../middleware/authentication");

describe("Student Portal — CSRF Exploitation & Mitigation Test Suite", () => {
  // Reset student data and default to secure mode before each test
  beforeEach(() => {
    resetStudentData();
    setLabMode("secure");
  });

  // ==========================================================================
  // Test 1: Unauthenticated user cannot change email
  // ==========================================================================
  it("Requirement 1: Unauthenticated user cannot change email address (returns 401)", async () => {
    const unauthenticatedAgent = request(app);

    // Attempt vulnerable endpoint without session
    const resVuln = await unauthenticatedAgent
      .get("/api/vulnerable/change-email?email=unauth@example.com")
      .set("Accept", "application/json");

    assert.equal(resVuln.status, 401, "Unauthenticated request should return 401");
    assert.equal(resVuln.body.success, false);

    // Attempt secure endpoint without session
    const resSec = await unauthenticatedAgent
      .post("/api/secure/change-email")
      .send({ email: "unauth@example.com" })
      .set("Accept", "application/json");

    assert.equal(resSec.status, 401, "Unauthenticated POST should return 401");
    assert.equal(resSec.body.success, false);

    // Verify student data remains untouched
    assert.equal(getStudent().email, "alex.johnson@university.edu");
  });

  // ==========================================================================
  // Test 2: Vulnerable local demonstration changes email via GET
  // ==========================================================================
  it("Requirement 2: Vulnerable mode successfully mutates email via HTTP GET", async () => {
    const agent = request.agent(app);

    // Authenticate fictional student
    const loginRes = await agent
      .post("/api/auth/login")
      .send({ username: "student", password: "Password123!" });
    assert.equal(loginRes.status, 200, "Login should succeed");

    // Enable Vulnerable Lab Mode
    await agent.post("/api/lab/mode").send({ mode: "vulnerable" });

    const forgedEmail = "compromised-via-get@evil-domain.com";

    // Trigger state change via GET
    const vulnRes = await agent
      .get(`/api/vulnerable/change-email?email=${encodeURIComponent(forgedEmail)}`)
      .set("Accept", "application/json");

    assert.equal(vulnRes.status, 200, "Vulnerable GET request should return 200");
    assert.equal(vulnRes.body.success, true);
    assert.equal(vulnRes.body.details.updatedEmail, forgedEmail);

    // Verify in-memory state changed without token or intent check
    assert.equal(getStudent().email, forgedEmail);
  });

  // ==========================================================================
  // Test 3: Original GET exploit fails to change email in secure mode
  // ==========================================================================
  it("Requirement 3: Original GET exploit fails to change email in secure mode (email remains unchanged)", async () => {
    const agent = request.agent(app);

    // Login
    await agent
      .post("/api/auth/login")
      .send({ username: "student", password: "Password123!" });

    // Explicitly enforce Secure Lab Mode
    await agent.post("/api/lab/mode").send({ mode: "secure" });

    const originalEmail = getStudent().email;
    const attackEmail = "blocked-exploit@evil-domain.com";

    // Trigger vulnerable route while in secure mode
    const res = await agent
      .get(`/api/vulnerable/change-email?email=${encodeURIComponent(attackEmail)}`)
      .set("Accept", "application/json");

    assert.equal(res.status, 405, "Vulnerable GET should be rejected in secure mode with 405 Method Not Allowed");
    assert.equal(res.headers["allow"], "POST", "Allow header must be set to POST");
    assert.equal(res.body.success, false);

    // Crucial check: Email must remain completely unchanged!
    assert.equal(getStudent().email, originalEmail, "Email address must remain unchanged");
  });

  // ==========================================================================
  // Test 4: Valid protected POST changes email successfully with valid CSRF token
  // ==========================================================================
  it("Requirement 4: Valid protected POST with valid CSRF token changes email successfully", async () => {
    const agent = request.agent(app);

    // Login
    await agent
      .post("/api/auth/login")
      .send({ username: "student", password: "Password123!" });

    // Fetch active session CSRF token
    const tokenRes = await agent.get("/api/secure/csrf-token");
    assert.equal(tokenRes.status, 200);
    const { csrfToken } = tokenRes.body;
    assert.ok(csrfToken, "CSRF token must be present");

    const newLegitimateEmail = "alex.johnson.new@university.edu";

    // Submit legitimate POST with token in header
    const updateRes = await agent
      .post("/api/secure/change-email")
      .set("x-csrf-token", csrfToken)
      .send({ email: newLegitimateEmail });

    assert.equal(updateRes.status, 200, "Protected POST should succeed with 200 OK");
    assert.equal(updateRes.body.success, true);
    assert.equal(updateRes.body.currentEmail, newLegitimateEmail);

    // Verify state was safely updated
    assert.equal(getStudent().email, newLegitimateEmail);

    // Token rotation check: verify a new token was generated and old token is invalidated
    assert.ok(updateRes.body.newCsrfToken, "New rotated CSRF token must be returned");
    assert.notEqual(updateRes.body.newCsrfToken, csrfToken, "CSRF token must rotate after successful mutation");

    const oldTokenAttempt = await agent
      .post("/api/secure/change-email")
      .set("x-csrf-token", csrfToken)
      .send({ email: "invalid-reuse@university.edu" });
    assert.equal(oldTokenAttempt.status, 403, "Reusing previous CSRF token must fail with 403");

    const rotatedSuccessAttempt = await agent
      .post("/api/secure/change-email")
      .set("x-csrf-token", updateRes.body.newCsrfToken)
      .send({ email: "alex.subsequent@university.edu" });
    assert.equal(rotatedSuccessAttempt.status, 200, "Subsequent POST with rotated token must succeed");
    assert.equal(getStudent().email, "alex.subsequent@university.edu");
  });

  // ==========================================================================
  // Test 5: POST with no CSRF token is rejected (403 Forbidden)
  // ==========================================================================
  it("Requirement 5: POST request with missing CSRF token is rejected with 403 Forbidden", async () => {
    const agent = request.agent(app);

    await agent
      .post("/api/auth/login")
      .send({ username: "student", password: "Password123!" });

    const originalEmail = getStudent().email;

    // Send POST without any CSRF token header or body field
    const res = await agent
      .post("/api/secure/change-email")
      .send({ email: "forged-post-no-token@evil.com" });

    assert.equal(res.status, 403, "Missing token must be rejected with 403");
    assert.equal(res.body.success, false);
    assert.equal(res.body.securityCode, "CSRF_TOKEN_MISSING");

    // Email remains unchanged
    assert.equal(getStudent().email, originalEmail);
  });

  // ==========================================================================
  // Test 6: POST with invalid CSRF token is rejected (403 Forbidden)
  // ==========================================================================
  it("Requirement 6: POST request with invalid/tampered CSRF token is rejected with 403 Forbidden", async () => {
    const agent = request.agent(app);

    await agent
      .post("/api/auth/login")
      .send({ username: "student", password: "Password123!" });

    const originalEmail = getStudent().email;

    // Send POST with forged/arbitrary token
    const res = await agent
      .post("/api/secure/change-email")
      .set("x-csrf-token", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
      .send({ email: "tampered-token@evil.com" });

    assert.equal(res.status, 403, "Tampered token must be rejected with 403");
    assert.equal(res.body.success, false);
    assert.equal(res.body.securityCode, "CSRF_TOKEN_MISMATCH");

    // Email remains unchanged
    assert.equal(getStudent().email, originalEmail);
  });

  // ==========================================================================
  // Test 7: GET request to secure update endpoint does not change state (405)
  // ==========================================================================
  it("Requirement 7: GET request to secure update endpoint is rejected with 405 Method Not Allowed", async () => {
    const agent = request.agent(app);

    await agent
      .post("/api/auth/login")
      .send({ username: "student", password: "Password123!" });

    const originalEmail = getStudent().email;

    // Try sending GET to secure change-email endpoint
    const res = await agent
      .get("/api/secure/change-email?email=get-to-secure@attacker.com");

    assert.equal(res.status, 405, "GET to secure endpoint must return 405 Method Not Allowed");
    assert.equal(res.headers["allow"], "POST", "Allow header must be set to POST");
    assert.equal(res.body.success, false);
    assert.equal(res.body.error, "Method Not Allowed");

    // State remains unaltered
    assert.equal(getStudent().email, originalEmail);
  });

  // ==========================================================================
  // Test 8: Invalid email input is rejected (400 Bad Request)
  // ==========================================================================
  it("Requirement 8: Invalid email format is rejected with 400 Bad Request", async () => {
    const agent = request.agent(app);

    await agent
      .post("/api/auth/login")
      .send({ username: "student", password: "Password123!" });

    const tokenRes = await agent.get("/api/secure/csrf-token");
    const { csrfToken } = tokenRes.body;

    const originalEmail = getStudent().email;

    // Submit invalid email syntax
    const res = await agent
      .post("/api/secure/change-email")
      .set("x-csrf-token", csrfToken)
      .send({ email: "not-an-email-address" });

    assert.equal(res.status, 400, "Invalid email must return 400 Bad Request");
    assert.equal(res.body.success, false);

    // Email remains unchanged
    assert.equal(getStudent().email, originalEmail);
  });

  // ==========================================================================
  // Test 9: Logout invalidates the authenticated session
  // ==========================================================================
  it("Requirement 9: Logout destroys session and blocks subsequent authenticated requests", async () => {
    const agent = request.agent(app);

    // Log in
    await agent
      .post("/api/auth/login")
      .send({ username: "student", password: "Password123!" });

    // Verify authenticated
    const meBefore = await agent.get("/api/auth/me");
    assert.equal(meBefore.status, 200);

    // Perform logout
    const logoutRes = await agent.post("/api/auth/logout");
    assert.equal(logoutRes.status, 200);
    assert.equal(logoutRes.body.success, true);

    // Subsequent call to /api/auth/me should fail with 401
    const meAfter = await agent.get("/api/auth/me").set("Accept", "application/json");
    assert.equal(meAfter.status, 401, "Session should be invalidated after logout");
  });

  // ==========================================================================
  // Test 10: Attacker website is served from a distinct origin
  // ==========================================================================
  it("Requirement 10: Attacker website is served by a distinct local origin and service", async () => {
    const res = await request(attackerApp).get("/health");
    assert.equal(res.status, 200, "Attacker health endpoint should return 200");
    assert.equal(res.body.service, "csrf-attacker-server");
    assert.ok(res.body.origin.includes("4000"), "Attacker origin must default to port 4000");
    assert.notEqual(res.body.origin, "http://localhost:3000", "Attacker origin must be distinct from Student Portal (port 3000)");
  });

  // ==========================================================================
  // Test 11: Attacker webpage contains required educational elements & no token leakage
  // ==========================================================================
  it("Requirement 11: Attacker webpage contains required deceptive Wi-Fi elements and does not leak tokens or private data", async () => {
    const res = await request(attackerApp).get("/");
    assert.equal(res.status, 200, "Attacker index page should return 200 OK");
    assert.equal(res.headers["content-type"].includes("text/html"), true);

    const html = res.text;
    // Required elements for Wi-Fi deceptive landing page
    assert.ok(html.includes("Free Public Wi-Fi"), "Must display Free Public Wi-Fi heading");
    assert.ok(html.includes("Connect Now"), "Must have Connect Now button");
    assert.ok(html.includes("attacker@evil.com"), "Must target demonstration email");
    assert.ok(html.includes("/api/vulnerable/change-email"), "Must target vulnerable endpoint");

    // Security constraints: Attacker page must not leak session cookies or tokens
    assert.ok(!html.includes("student_portal_sid"), "Must not embed or expose student session cookie");
    assert.ok(!html.includes("Password123!"), "Must not contain hardcoded student passwords");
  });

  // ==========================================================================
  // Test 12: Insecure demonstration configuration permits authenticated GET email mutation
  // ==========================================================================
  it("Requirement 12: Vulnerable GET changes email when authenticated & permitted; verified directly via server state", async () => {
    const agent = request.agent(app);

    // Login as student
    await agent
      .post("/api/auth/login")
      .send({ username: "student", password: "Password123!" });

    // Enable vulnerable mode
    await agent.post("/api/lab/mode").send({ mode: "vulnerable" });

    const targetAttackEmail = "cross-site-victim@attacker.test";

    // Dispatch vulnerable GET
    const res = await agent
      .get(`/api/vulnerable/change-email?email=${encodeURIComponent(targetAttackEmail)}`)
      .set("Accept", "application/json");

    assert.equal(res.status, 200);
    assert.equal(res.body.success, true);

    // CRITICAL: Verify directly against internal backend state (not a frontend message)
    assert.equal(getStudent().email, targetAttackEmail, "Server in-memory student email must reflect the mutation");
  });

  // ==========================================================================
  // Test 13: Attacker cannot access or forge synchronizer CSRF tokens across origins
  // ==========================================================================
  it("Requirement 13: Unauthenticated / cross-origin requests cannot obtain synchronizer CSRF tokens", async () => {
    // Unauthenticated request to portal's token route fails
    const unauthRes = await request(app)
      .get("/api/secure/csrf-token")
      .set("Accept", "application/json");

    assert.equal(unauthRes.status, 401, "CSRF token endpoint must require authentication");
    assert.equal(unauthRes.body.csrfToken, undefined, "No CSRF token should be returned to unauthenticated origin");

    // Attacker server has no endpoint that yields the student portal's CSRF token
    const attackerCfgRes = await request(attackerApp).get("/api/config");
    assert.equal(attackerCfgRes.status, 200);
    assert.equal(attackerCfgRes.body.csrfToken, undefined, "Attacker config must not contain portal CSRF token");
  });

  // ==========================================================================
  // Test 14: Comprehensive verification of mode enforcement
  // ==========================================================================
  it("Requirement 14: Enforces HTTP 405 on state-changing GET in Secure Mode while allowing GET in Vulnerable Mode", async () => {
    const agent = request.agent(app);

    // Authenticate
    await agent
      .post("/api/auth/login")
      .send({ username: "student", password: "Password123!" });

    // Step A: Switch to Secure Mode -> GET must be rejected with 405
    setLabMode("secure");
    const secureGetRes = await agent
      .get("/api/vulnerable/change-email?email=test-secure@evil.com")
      .set("Accept", "application/json");

    assert.equal(secureGetRes.status, 405, "Secure mode must reject GET with 405 Method Not Allowed");
    assert.equal(secureGetRes.headers["allow"], "POST", "Must include Allow: POST header");
    assert.equal(getStudent().email, "alex.johnson@university.edu", "Email must not be changed in secure mode");

    // Step B: Switch to Vulnerable Mode -> GET must succeed with 200
    setLabMode("vulnerable");
    const vulnGetRes = await agent
      .get("/api/vulnerable/change-email?email=test-vulnerable@evil.com")
      .set("Accept", "application/json");

    assert.equal(vulnGetRes.status, 200, "Vulnerable mode must allow state-changing GET");
    assert.equal(getStudent().email, "test-vulnerable@evil.com", "Email must be changed in vulnerable mode");
  });
});

